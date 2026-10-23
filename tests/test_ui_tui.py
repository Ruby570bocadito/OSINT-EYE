"""Offline tests for the Textual TUI (ui/tui_app.py).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""



class TestTuiRecordCoercion:
    def test_string_value_becomes_single_element_list(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values("1.2.3.4") == ["1.2.3.4"]

    def test_list_values_are_stringified(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values(["a", 1]) == ["a", "1"]

    def test_junk_is_dropped(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values(5) == []
        assert ScanScreen._coerce_record_values(None) == []
