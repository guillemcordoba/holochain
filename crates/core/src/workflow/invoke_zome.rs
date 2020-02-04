use crate::{
    agent::SourceChain,
    nucleus::{ZomeInvocation, ZomeInvocationResult},
    ribosome::Ribosome,
    txn::source_chain,
};
use sx_types::{error::SkunkResult, shims::*};

pub async fn invoke_zome(
    invocation: ZomeInvocation,
    source_chain: SourceChain<'_>,
    cursor_rw: source_chain::CursorRw,
) -> SkunkResult<ZomeInvocationResult> {
    let dna = source_chain.dna()?;
    let ribosome = Ribosome::new(dna);
    let (result, cursor_rw) = ribosome.call_zome_function(cursor_rw, invocation)?;
    source_chain.try_commit(cursor_rw)?;
    Ok(result)
}