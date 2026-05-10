from app.workflow import validate_sod

def test_sod_all_six_overlaps():
    assert validate_sod(1,1,3) != []  # initiator = reviewer
    assert validate_sod(1,2,2) != []  # reviewer  = approver
    assert validate_sod(1,2,1) != []  # initiator = approver
    assert validate_sod(1,1,1) != []  # all same
    assert validate_sod(1,2,3) == []  # all different - passes

