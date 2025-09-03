//! Example: TLS client using `ktls`.

use std::error::Error;

use ktls_test::common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (ret1, ret2, ret3, ret4) = tokio::join!(
        common::run_echo_test(common::CloseParty::Client, common::TestOption::empty()),
        common::run_echo_test(
            common::CloseParty::Client,
            common::TestOption::HANDLE_IO_RESULT
        ),
        common::run_echo_test(common::CloseParty::Server, common::TestOption::empty()),
        common::run_echo_test(
            common::CloseParty::Server,
            common::TestOption::HANDLE_IO_RESULT
        ),
    );

    ret1?;
    ret2?;
    ret3?;
    ret4?;

    Ok(())
}
