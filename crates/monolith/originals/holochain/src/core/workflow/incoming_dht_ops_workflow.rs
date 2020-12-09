//! The workflow and queue consumer for DhtOp integration

use super::error::WorkflowResult;
use super::integrate_dht_ops_workflow::integrate_single_data;
use super::integrate_dht_ops_workflow::integrate_single_metadata;
use super::produce_dht_ops_workflow::dht_op_light::error::DhtOpConvertResult;
use super::sys_validation_workflow::counterfeit_check;
use crate::holochain::core::queue_consumer::TriggerSender;
use crate::holochain::core::state::dht_op_integration::IntegratedDhtOpsStore;
use crate::holochain::core::state::dht_op_integration::IntegrationLimboStore;
use crate::holochain::core::state::element_buf::ElementBuf;
use crate::holochain::core::state::metadata::MetadataBuf;
use crate::holochain::core::state::metadata::MetadataBufT;
use crate::holochain::core::state::validation_db::ValidationLimboStatus;
use crate::holochain::core::state::validation_db::ValidationLimboStore;
use crate::holochain::core::state::validation_db::ValidationLimboValue;
use crate::holochain::core::state::workspace::Workspace;
use crate::holochain::core::state::workspace::WorkspaceResult;
use holo_hash::AgentPubKey;
use holo_hash::DhtOpHash;
use crate::holochain_state::buffer::BufferedStore;
use crate::holochain_state::buffer::KvBufFresh;
use crate::holochain_state::db::INTEGRATED_DHT_OPS;
use crate::holochain_state::db::INTEGRATION_LIMBO;
use crate::holochain_state::env::EnvironmentWrite;
use crate::holochain_state::error::DatabaseResult;
use crate::holochain_state::prelude::EnvironmentRead;
use crate::holochain_state::prelude::GetDb;
use crate::holochain_state::prelude::IntegratedPrefix;
use crate::holochain_state::prelude::PendingPrefix;
use crate::holochain_state::prelude::Writer;
use crate::holochain_types::dht_op::DhtOp;
use crate::holochain_types::Timestamp;
use holochain_zome_types::query::HighestObserved;
use tracing::instrument;

#[cfg(test)]
mod test;

#[instrument(skip(state_env, sys_validation_trigger, ops))]
pub async fn incoming_dht_ops_workflow(
    state_env: &EnvironmentWrite,
    mut sys_validation_trigger: TriggerSender,
    ops: Vec<(holo_hash::DhtOpHash, crate::holochain_types::dht_op::DhtOp)>,
    from_agent: Option<AgentPubKey>,
) -> WorkflowResult<()> {
    // set up our workspace
    let mut workspace = IncomingDhtOpsWorkspace::new(state_env.clone().into())?;

    // add incoming ops to the validation limbo
    for (hash, op) in ops {
        if !workspace.op_exists(&hash)? {
            tracing::debug!(?hash, ?op);
            if should_keep(&op).await? {
                workspace
                    .add_to_pending(hash, op, from_agent.clone())
                    .await?;
            } else {
                tracing::warn!(
                    msg = "Dropping op because it failed counterfeit checks",
                    ?op
                );
            }
        }
    }

    // commit our transaction
    let writer: crate::holochain::core::queue_consumer::OneshotWriter = state_env.clone().into();

    writer.with_writer(|writer| Ok(workspace.flush_to_txn(writer)?))?;

    // trigger validation of queued ops
    sys_validation_trigger.trigger();

    Ok(())
}

/// If this op fails the counterfeit check it should be dropped
async fn should_keep(op: &DhtOp) -> WorkflowResult<bool> {
    let header = op.header();
    let signature = op.signature();
    Ok(counterfeit_check(signature, &header).await?)
}

#[allow(missing_docs)]
pub struct IncomingDhtOpsWorkspace {
    pub integration_limbo: IntegrationLimboStore,
    pub integrated_dht_ops: IntegratedDhtOpsStore,
    pub validation_limbo: ValidationLimboStore,
    pub element_pending: ElementBuf<PendingPrefix>,
    pub meta_pending: MetadataBuf<PendingPrefix>,
    pub meta_integrated: MetadataBuf<IntegratedPrefix>,
}

impl Workspace for IncomingDhtOpsWorkspace {
    fn flush_to_txn_ref(&mut self, writer: &mut Writer) -> WorkspaceResult<()> {
        self.validation_limbo.0.flush_to_txn_ref(writer)?;
        self.element_pending.flush_to_txn_ref(writer)?;
        self.meta_pending.flush_to_txn_ref(writer)?;
        self.meta_integrated.flush_to_txn_ref(writer)?;
        Ok(())
    }
}

impl IncomingDhtOpsWorkspace {
    pub fn new(env: EnvironmentRead) -> WorkspaceResult<Self> {
        let db = env.get_db(&*INTEGRATED_DHT_OPS)?;
        let integrated_dht_ops = KvBufFresh::new(env.clone(), db);

        let db = env.get_db(&*INTEGRATION_LIMBO)?;
        let integration_limbo = KvBufFresh::new(env.clone(), db);

        let validation_limbo = ValidationLimboStore::new(env.clone())?;

        let element_pending = ElementBuf::pending(env.clone())?;
        let meta_pending = MetadataBuf::pending(env.clone())?;

        let meta_integrated = MetadataBuf::vault(env)?;

        Ok(Self {
            integration_limbo,
            integrated_dht_ops,
            validation_limbo,
            element_pending,
            meta_pending,
            meta_integrated,
        })
    }

    async fn add_to_pending(
        &mut self,
        hash: DhtOpHash,
        op: DhtOp,
        from_agent: Option<AgentPubKey>,
    ) -> DhtOpConvertResult<()> {
        let basis = op.dht_basis();
        let op_light = op.to_light();
        tracing::debug!(?op_light);

        // register the highest observed header in an agents chain
        if let DhtOp::RegisterAgentActivity(_, header) = &op {
            self.meta_integrated.register_activity_observed(
                header.author(),
                HighestObserved {
                    header_seq: header.header_seq(),
                    hash: vec![op_light.header_hash().clone()],
                },
            )?;
        }

        integrate_single_data(op, &mut self.element_pending)?;
        integrate_single_metadata(
            op_light.clone(),
            &self.element_pending,
            &mut self.meta_pending,
        )?;
        let vlv = ValidationLimboValue {
            status: ValidationLimboStatus::Pending,
            op: op_light,
            basis,
            time_added: Timestamp::now(),
            last_try: None,
            num_tries: 0,
            from_agent,
        };
        self.validation_limbo.put(hash, vlv)?;
        Ok(())
    }

    pub fn op_exists(&self, hash: &DhtOpHash) -> DatabaseResult<bool> {
        Ok(self.integrated_dht_ops.contains(&hash)?
            || self.integration_limbo.contains(&hash)?
            || self.validation_limbo.contains(&hash)?)
    }
}