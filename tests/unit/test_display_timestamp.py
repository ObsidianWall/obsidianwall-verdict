from cli.display import format_display_timestamp


def test_format_display_timestamp_includes_fractional_seconds() -> None:
    assert (
        format_display_timestamp("2026-08-11T02:09:15.123456+00:00")
        == "2026-08-11 02:09:15.123456 UTC"
    )
