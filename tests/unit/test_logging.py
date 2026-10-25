import logging

from logger import configure_logging, get_logger


def test_quiet_keeps_errors_and_debug_reaches_analysis_loggers():
    log = get_logger("ioc_inspector_core.pdf_parser")
    handlers = [h for h in log.handlers if not isinstance(h, logging.FileHandler)]
    try:
        configure_logging(quiet=True, debug=True)
        assert log.level == logging.DEBUG
        assert all(h.level == logging.ERROR for h in handlers)
        configure_logging(debug=True)
        assert all(h.level == logging.DEBUG for h in handlers)
    finally:
        configure_logging()
