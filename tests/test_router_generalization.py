import pytest
from nyx.core.router import recommend_skills, rank_attack_surface


def test_router_generalization_user_registration():
    # Test arbitrary user creation endpoints across different URL conventions
    endpoints = [
        "https://api.example.com/v1/user/create",
        "https://service.corp.internal/signup",
        "https://saas.app.io/api/v2/accounts/register",
        "https://portal.target.com/adduser.php"
    ]
    for ep in endpoints:
        rec = recommend_skills(ep)
        skills = rec["recommended_skills"]
        surfaces = rec["attack_surface"]
        assert "hunt-api-misconfig" in skills, f"Failed on {ep}: {skills}"
        assert "hunt-exceptional-conditions" in skills, f"Failed on {ep}: {skills}"
        assert any(s in surfaces for s in ("registration", "mass_assignment", "input_validation"))
        assert rec["priority"] == "HIGH"


def test_router_generalization_business_logic_e_commerce():
    # Test arbitrary e-commerce, checkout, rating, and promo code endpoints
    endpoints = [
        "https://store.brand.com/api/v1/cart/items?quantity=2&price=19.99",
        "https://booking.travel.org/checkout/apply-promo?discount_code=SUMMER2026",
        "https://feedback.service.net/rest/v1/ratings/submit?stars=5",
        "https://streaming.app.io/api/v2/membership/upgrade?tier=premium"
    ]
    for ep in endpoints:
        rec = recommend_skills(ep)
        skills = rec["recommended_skills"]
        surfaces = rec["attack_surface"]
        assert "hunt-business-logic" in skills, f"Failed on {ep}: {skills}"
        assert "hunt-exceptional-conditions" in skills, f"Failed on {ep}: {skills}"
        assert any(s in surfaces for s in ("business_logic", "financial_tampering", "input_validation"))
        assert rec["priority"] == "HIGH"


def test_router_generalization_file_serving_and_lfi():
    # Test arbitrary document view, file download, and path endpoints
    endpoints = [
        "https://docs.corp.com/view/document?file=annual_report.pdf",
        "https://files.internal.net/ftp/reports/summary.md",
        "https://cloud.storage.io/static/downloads/data.zip"
    ]
    for ep in endpoints:
        rec = recommend_skills(ep)
        skills = rec["recommended_skills"]
        surfaces = rec["attack_surface"]
        assert "hunt-lfi" in skills, f"Failed on {ep}: {skills}"
        assert any(s in surfaces for s in ("file_serving", "path_traversal", "information_disclosure"))
        assert rec["priority"] == "HIGH"


def test_router_generalization_jwt_cryptography():
    # Test JWT keys, tokens, and jwks endpoints
    endpoints = [
        "https://auth.service.com/.well-known/jwks.json",
        "https://api.banking.io/v1/jwt/verify-token",
        "https://identity.company.org/oauth/v2/bearer/keystore"
    ]
    for ep in endpoints:
        rec = recommend_skills(ep)
        skills = rec["recommended_skills"]
        surfaces = rec["attack_surface"]
        assert "hunt-jwt-crypto" in skills, f"Failed on {ep}: {skills}"
        assert any(s in surfaces for s in ("cryptography", "jwt", "session"))
        assert rec["priority"] == "HIGH"
