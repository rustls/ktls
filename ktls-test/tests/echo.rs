//! Test: echo server

use std::io;

use ktls_test::common;

#[test_case::test_matrix(
    [
        common::CloseParty::Client,
        common::CloseParty::Server,
    ],
    [
        common::TestOption::empty(),
        common::TestOption::HANDLE_IO_RESULT,
    ]
)]
#[tokio::test]
async fn test_echo(
    close_party: common::CloseParty,
    test_option: common::TestOption,
) -> io::Result<()> {
    common::run_echo_test(close_party, test_option).await
}
