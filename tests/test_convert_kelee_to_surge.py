from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from convert_kelee_to_surge import convert_mock_response_options  # noqa: E402


class ConvertMockResponseOptionsTest(unittest.TestCase):
    def test_json_mock_body_is_encoded_as_surge_base64_data(self) -> None:
        body = '{"code":0,"msg":""}'
        encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")

        converted = convert_mock_response_options(f'data-type=json data="{body}" status-code=200')

        self.assertEqual(
            converted,
            f'data-type=base64 data="{encoded}" status-code=200 header="Content-Type:application/json"',
        )

    def test_loon_base64_mock_flag_becomes_surge_base64_data_type(self) -> None:
        converted = convert_mock_response_options('data-type=text data="AAAAAAA=" mock-data-is-base64=true')

        self.assertEqual(converted, 'data-type=base64 data="AAAAAAA=" status-code=200')


if __name__ == "__main__":
    unittest.main()
