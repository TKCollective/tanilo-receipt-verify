"""0.1.2: the reason for a non-list `signatures` names the actual problem.

Found while running Marcus Still's (stillmarcus24) malformed-input corpus and
reported on x402-foundation/tsc#4 on 2026-09-26: 0.1.1's reason "signatures
must be a list of objects (dicts); at least one entry was not" also fires when
`signatures` is not a list at all -- a string, a number, an object.
There are no entries in that case, so "at least one entry was not" describes a
problem the input doesn't have. Falsy non-list values ("", 0, {}, false) were
worse: they skipped the shape check and reported "missing payload or
signatures", although the member is present.

The status is unchanged in every case: `invalid`. Only the reason changes.
"""

import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tanilo_receipt_verify import verify  # noqa: E402
from tanilo_receipt_verify.verify import STATUS_INVALID  # noqa: E402

PAYLOAD = "eyJhIjoxfQ"
OLD_ENTRY_WORDING = "at least one entry was not"

NOT_A_LIST = [
    pytest.param("not-a-list", "a string", id="string"),
    pytest.param("", "a string", id="empty-string"),
    pytest.param(5, "a number", id="int"),
    pytest.param(0, "a number", id="zero"),
    pytest.param(1.5, "a number", id="float"),
    pytest.param({"protected": "x", "signature": "y"}, "an object", id="dict"),
    pytest.param({}, "an object", id="empty-dict"),
    pytest.param(True, "a boolean", id="true"),
    pytest.param(False, "a boolean", id="false"),
]


@pytest.mark.parametrize("signatures,json_type", NOT_A_LIST)
def test_non_list_signatures_reason_names_the_type(signatures, json_type):
    r = verify({"payload": PAYLOAD, "signatures": signatures})
    assert r.status == STATUS_INVALID
    assert len(r.errors) == 1
    reason = r.errors[0]
    assert OLD_ENTRY_WORDING not in reason
    assert "missing" not in reason
    assert reason == f"signatures must be a list (JSON array) of signature objects; got {json_type}"


@pytest.mark.parametrize(
    "signatures",
    [pytest.param(["a"], id="list-of-string"), pytest.param([{"protected": "", "signature": ""}, 3], id="list-with-int")],
)
def test_list_with_non_object_entry_keeps_entry_wording(signatures):
    r = verify({"payload": PAYLOAD, "signatures": signatures})
    assert r.status == STATUS_INVALID
    assert r.errors == ["signatures must be a list of objects (dicts); at least one entry was not"]


@pytest.mark.parametrize(
    "envelope",
    [
        pytest.param({"payload": PAYLOAD}, id="absent"),
        pytest.param({"payload": PAYLOAD, "signatures": None}, id="null"),
        pytest.param({"payload": PAYLOAD, "signatures": []}, id="empty-list"),
    ],
)
def test_absent_null_or_empty_signatures_still_reported_missing(envelope):
    r = verify(envelope)
    assert r.status == STATUS_INVALID
    assert r.errors == ["missing payload or signatures"]
