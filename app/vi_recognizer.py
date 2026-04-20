from presidio_analyzer import Pattern, PatternRecognizer

def build_vi_recognizers():
    """
    Tạo danh sách custom recognizer cho dữ liệu nhạy cảm Việt Nam.
    Mỗi recognizer là một Pattern class đăng ký vào Presidio.
    """

    # -------- CCCD / CMND --------
    # CCCD mới: 12 số liên tiếp
    # CMND cũ: 9 số
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        patterns=[
            Pattern(
                name="cccd_12",
                regex=r"\b\d{12}\b",
                score=0.85
            ),
            Pattern(
                name="cmnd_9",
                regex=r"\b\d{9}\b",
                score=0.6   # score thấp hơn vì 9 số dễ false positive
            ),
        ],
        context=["cccd", "cmnd", "căn cước", "chứng minh", "identity", "id card"]
    )

    # -------- Mã số thuế --------
    # MST cá nhân: 10 số
    # MST doanh nghiệp: 10 số + "-" + 3 số (0123456789-001)
    tax_recognizer = PatternRecognizer(
        supported_entity="VN_TAX_CODE",
        patterns=[
            Pattern(
                name="mst_10",
                regex=r"\b\d{10}\b",
                score=0.7
            ),
            Pattern(
                name="mst_13",
                regex=r"\b\d{10}-\d{3}\b",
                score=0.9
            ),
        ],
        context=["mã số thuế", "mst", "tax", "mã thuế", "tax code"]
    )

    # -------- Biển số xe --------
    # Format: 51A-123.45 hoặc 51A-12345
    license_plate_recognizer = PatternRecognizer(
        supported_entity="VN_LICENSE_PLATE",
        patterns=[
            Pattern(
                name="bien_so",
                regex=r"\b\d{2}[A-Z]{1,2}[-\s]\d{3,5}\.?\d{0,2}\b",
                score=0.85
            ),
        ],
        context=["biển số", "bien so", "xe", "phương tiện", "vehicle"]
    )

    # -------- Số tài khoản ngân hàng --------
    # Thường 9-14 số, cần context "ngân hàng" để tránh false positive
    bank_account_recognizer = PatternRecognizer(
        supported_entity="VN_BANK_ACCOUNT",
        patterns=[
            Pattern(
                name="stk",
                regex=r"\b\d{9,14}\b",
                score=0.6   # score thấp, cần context
            ),
        ],
        context=["tài khoản", "stk", "số tài khoản", "ngân hàng", "bank",
                 "vietcombank", "techcombank", "bidv", "agribank", "mb bank",
                 "chuyển khoản", "transfer"]
    )

    # -------- Họ tên người Việt --------
    # Pattern: 2-4 từ, mỗi từ viết hoa chữ đầu
    # Chỉ match khi có context rõ ràng
    vn_name_recognizer = PatternRecognizer(
        supported_entity="VN_PERSON_NAME",
        patterns=[
            Pattern(
                name="ho_ten",
                regex=r"\b([A-ZÁÀẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬĐÉÈẺẼẸÊẾỀỂỄỆÍÌỈĨỊÓÒỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÚÙỦŨỤƯỨỪỬỮỰÝỲỶỸỴ][a-záàảãạăắằẳẵặâấầẩẫậđéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ]+\s){2,3}[A-ZÁÀẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬĐÉÈẺẼẸÊẾỀỂỄỆÍÌỈĨỊÓÒỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÚÙỦŨỤƯỨỪỬỮỰÝỲỶỸỴ][a-záàảãạăắằẳẵặâấầẩẫậđéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ]+\b",
                score=0.6
            ),
        ],
        context=["tên", "nhân viên", "họ tên", "người dùng", "user",
                 "giám đốc", "trưởng phòng", "name", "ký tên", "signed by"]
    )

    return [
        cccd_recognizer,
        tax_recognizer,
        license_plate_recognizer,
        bank_account_recognizer,
        vn_name_recognizer,
    ]