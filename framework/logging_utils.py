from __future__ import annotations
import logging
import sys
from pathlib import Path
from typing import Optional, Union

def setup_logging(*, console_level: int=logging.WARNING, file_path: Optional[Union[str, Path]]=None, file_level: int=logging.DEBUG, replace_existing: bool=True) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    if replace_existing:
        root.handlers.clear()
    console_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler) and (not isinstance(h, logging.FileHandler))]
    if not console_handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handlers = [console_handler]
        root.addHandler(console_handler)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    for handler in console_handlers:
        handler.setLevel(console_level)
        handler.setFormatter(console_formatter)
    if file_path:
        path_obj = Path(file_path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        existing_file_handler = None
        for handler in root.handlers:
            if isinstance(handler, logging.FileHandler):
                if Path(getattr(handler, 'baseFilename', '')) == path_obj:
                    existing_file_handler = handler
                    break
        if existing_file_handler is None:
            mode = 'w' if replace_existing else 'a'
            file_handler = logging.FileHandler(path_obj, mode=mode, encoding='utf-8')
            file_handler.setLevel(file_level)
            file_handler.setFormatter(console_formatter)
            root.addHandler(file_handler)
        else:
            existing_file_handler.setLevel(file_level)
            existing_file_handler.setFormatter(console_formatter)
