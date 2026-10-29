"""The frontend in a real browser (headless Chromium), against the stack started by tests/e2e/run.sh.

Install the browser once with `uv run playwright install --only-shell chromium`.
"""

import re

import pytest

from tests.e2e.test_e2e import BASE_URL, make_csr

playwright = pytest.importorskip("playwright.sync_api")
expect = playwright.expect

pytestmark = pytest.mark.skipif(not BASE_URL, reason="needs the stack started by tests/e2e/run.sh")

PAGES = [
    ("/", "Dashboard"),
    ("/certificates", "Certificates"),
    ("/certificates?status=expiring", "Certificates"),
    ("/certificates?status=revoked", "Certificates"),
    ("/acme/accounts", "ACME accounts"),
    ("/acme/orders", "ACME orders"),
    ("/acme/authorizations", "ACME authorizations"),
    ("/acme/challenges", "ACME challenges"),
    ("/acme/certificates", "ACME certificates"),
    ("/ca", "CA status"),
    ("/provisioners", "Provisioners"),
    ("/admins", "Admins"),
    ("/settings", "Settings"),
    ("/audit", "Audit log"),
    ("/search?q=acme", "Results for “acme”"),
]


@pytest.fixture(scope="module")
def browser():
    with playwright.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except playwright.Error as e:
            pytest.skip(f"no browser: {e.message.splitlines()[0]}")
        yield chromium
        chromium.close()


@pytest.fixture
def page(browser):
    context = browser.new_context(base_url=BASE_URL)
    page = context.new_page()
    # Script errors, and anything the Content-Security-Policy refused
    problems = []
    page.on("console", lambda message: message.type == "error" and problems.append(message.text))
    page.on("pageerror", lambda error: problems.append(str(error)))
    page.problems = problems
    yield page
    context.close()


def sign_in(page, path="/"):
    page.goto(path)
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("testpw")
    page.get_by_role("button", name="Sign in").click()


def test_signing_in_and_out(page):
    sign_in(page, "/provisioners")
    # Back where the sign-in started
    expect(page.get_by_role("heading", name="Provisioners", exact=True)).to_be_visible()
    page.get_by_role("button", name="admin").click()
    page.get_by_role("menuitem", name="Sign out").click()
    expect(page.get_by_role("button", name="Sign in")).to_be_visible()
    page.goto("/certificates")
    expect(page.get_by_role("button", name="Sign in")).to_be_visible()


def test_a_wrong_password_is_explained(page):
    page.goto("/login")
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password").fill("wrong")
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_role("alert")).to_have_text("Invalid username or password.")


def test_every_page_renders_without_errors(page):
    sign_in(page)
    expect(page.get_by_text("Expiry horizon")).to_be_visible()
    for path, heading in PAGES:
        page.goto(path)
        expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()
        # The page's data, not a loading placeholder
        expect(page.locator("[aria-busy=true]")).to_have_count(0)
    assert page.problems == []


def test_sign_a_csr_then_revoke_it(page):
    csr = make_csr("e2e-browser.test", "browser")
    sign_in(page, "/certificates")
    page.get_by_role("button", name="Sign a CSR").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("CSR (PEM)").fill(csr)
    # What the CSR asks for, before signing
    expect(dialog.get_by_text("CN=e2e-browser.test")).to_be_visible()
    dialog.get_by_label("Provisioner password").fill("testpass")
    dialog.get_by_role("button", name="Sign certificate").click()

    expect(page.get_by_role("heading", name=re.compile("e2e-browser.test"))).to_be_visible()
    expect(page.get_by_text("Valid", exact=True).first).to_be_visible()
    page.get_by_role("button", name="Revoke").click()
    alert = page.get_by_role("alertdialog")
    alert.get_by_label("Reason").click()
    page.get_by_role("option", name="Superseded").click()
    alert.get_by_role("button", name="Revoke certificate").click()

    expect(page.get_by_role("status").filter(has_text="revoked")).to_be_visible()
    expect(page.get_by_text("Superseded (code 4)")).to_be_visible()
    assert page.problems == []


def test_old_bookmarks_open_the_new_pages(page):
    sign_in(page, "/x509/revoked")
    expect(page).to_have_url(re.compile(r"/certificates\?status=revoked$"))
    expect(page.get_by_role("tab", name="Revoked", selected=True)).to_be_visible()


def test_the_list_filter_and_csv_export(page):
    sign_in(page, "/certificates")
    page.get_by_label("Filter by name or serial").fill("acme-client")
    expect(page).to_have_url(re.compile(r"q=acme-client"))
    rows = page.get_by_role("table", name="Certificates").locator("tbody tr")
    expect(rows).to_have_count(1)
    with page.expect_download() as download:
        page.get_by_role("link", name="Export CSV").click()
    lines = open(download.value.path()).read().splitlines()
    assert lines[0].startswith("serial,serial_hex,status") and len(lines) == 2
