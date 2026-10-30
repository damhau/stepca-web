"""The frontend in a real browser (headless Chromium), against the stack started by tests/e2e/run.sh.

Install the browser once with `uv run playwright install --only-shell chromium`.
"""

import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests.e2e.test_e2e import BASE_URL, make_csr

playwright = pytest.importorskip("playwright.sync_api")
expect = playwright.expect

pytestmark = pytest.mark.skipif(not BASE_URL, reason="needs the stack started by tests/e2e/run.sh")

PAGES = [
    ("/", "Overview"),
    ("/certificates", "Certificates"),
    ("/certificates?tab=expiring", "Certificates"),
    ("/certificates?tab=revoked", "Certificates"),
    ("/acme/orders", "ACME"),
    ("/acme/accounts", "ACME"),
    ("/acme/authorizations", "ACME"),
    ("/acme/challenges", "ACME"),
    ("/acme/certificates", "ACME"),
    ("/provisioners", "Provisioners"),
    ("/provisioners/acme-e2e", "acme-e2e"),
    ("/ca", "Authority"),
    ("/ca?tab=configuration", "Authority"),
    ("/admins", "Admins"),
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
    expect(page.get_by_role("button", name="Signed in as admin")).to_be_visible()


def sheet(page):
    return page.locator("aside[aria-label='Certificate details']")


def test_signing_in_and_out(page):
    sign_in(page, "/provisioners")
    # Back where the sign-in started
    expect(page.get_by_role("heading", name="Provisioners", exact=True)).to_be_visible()
    page.get_by_role("button", name="Signed in as admin").click()
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
    expect(page.get_by_text("Production readiness")).to_be_visible()
    for path, heading in PAGES:
        page.goto(path)
        expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()
        # The page's data, not a loading placeholder
        expect(page.locator("[aria-busy=true]")).to_have_count(0)
    assert page.problems == []


def test_issue_from_an_uploaded_csr_then_revoke_it(page):
    csr = make_csr("e2e-browser.test", "browser")
    sign_in(page, "/certificates")
    page.get_by_role("button", name="New certificate").click()
    dialog = page.get_by_role("dialog", name="New certificate")
    dialog.get_by_role("radio", name=re.compile("Upload a CSR")).check()
    dialog.get_by_label("Certificate signing request").fill(csr)
    # What the CSR asks for, before signing
    expect(dialog.get_by_text("CN=e2e-browser.test")).to_be_visible()
    dialog.get_by_role("button", name="Continue").click()
    # The first JWK provisioner, Admin JWK, is picked
    dialog.get_by_label("Provisioner password").fill("testpass")
    dialog.get_by_role("button", name="Continue").click()
    dialog.get_by_role("button", name="Issue certificate").click()
    expect(dialog.get_by_text("Certificate issued")).to_be_visible()
    dialog.get_by_role("button", name="Back to certificates").click()

    details = sheet(page)
    expect(details.get_by_text("e2e-browser.test").first).to_be_visible()
    details.get_by_role("button", name="Revoke").click()
    alert = page.get_by_role("alertdialog")
    alert.get_by_label("Reason").click()
    page.get_by_role("option", name="Superseded").click()
    alert.get_by_role("button", name="Revoke certificate").click()
    expect(details.get_by_text("Superseded (code 4)")).to_be_visible()
    assert page.problems == []


def test_issue_with_a_key_made_in_the_browser(page):
    sign_in(page, "/certificates")
    page.get_by_role("button", name="New certificate").click()
    dialog = page.get_by_role("dialog", name="New certificate")
    dialog.get_by_label("Common name").fill("e2e-keygen.test")
    dialog.get_by_label("Subject alternative names").fill("alt.e2e-keygen.test")
    dialog.get_by_role("button", name="Add", exact=True).click()
    dialog.get_by_role("button", name="Continue").click()
    dialog.get_by_label("Provisioner password").fill("testpass")
    dialog.get_by_label("Key type").click()
    page.get_by_role("option", name="Ed25519").click()
    dialog.get_by_role("button", name="Continue").click()
    # The common name is always one of the names
    expect(dialog.get_by_text("e2e-keygen.test, alt.e2e-keygen.test")).to_be_visible()
    dialog.get_by_role("button", name="Issue certificate").click()
    expect(dialog.get_by_text("Certificate issued")).to_be_visible()

    with page.expect_download() as download:
        dialog.get_by_role("button", name=re.compile("^Private key")).click()
    key = serialization.load_pem_private_key(open(download.value.path(), "rb").read(), password=None)
    with page.expect_download() as download:
        dialog.get_by_role("button", name=re.compile("^PEM bundle")).click()
    # The certificate, its chain, then the key
    chain, _, rest = open(download.value.path()).read().partition("-----BEGIN PRIVATE KEY-----")
    cert, intermediate = x509.load_pem_x509_certificates(chain.encode())
    assert rest and cert.issuer == intermediate.subject
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    assert cert.public_key().public_bytes(*raw) == key.public_key().public_bytes(*raw)
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert names == ["e2e-keygen.test", "alt.e2e-keygen.test"]
    assert page.problems == []


def test_old_bookmarks_open_the_new_pages(page):
    sign_in(page, "/x509/revoked")
    expect(page).to_have_url(re.compile(r"/certificates\?tab=revoked$"))
    expect(page.get_by_role("tab", name=re.compile("^Revoked"), selected=True)).to_be_visible()


def test_the_list_search_selection_and_csv_export(page):
    sign_in(page, "/certificates")
    page.get_by_label("Search by name, SAN or serial").fill("acme-client")
    expect(page).to_have_url(re.compile(r"q=acme-client"))
    rows = page.get_by_role("region", name="Certificate list").locator("tbody tr")
    expect(rows).to_have_count(1)
    rows.get_by_role("checkbox").check()
    expect(page.get_by_text("1 selected")).to_be_visible()
    with page.expect_download() as download:
        page.get_by_role("link", name="Export").click()
    lines = open(download.value.path()).read().splitlines()
    assert lines[0].startswith("serial,serial_hex,status") and len(lines) == 2


def test_the_command_palette_finds_a_certificate(page):
    sign_in(page)
    page.keyboard.press("Control+k")
    palette = page.get_by_role("dialog", name="Search or run a command")
    palette.get_by_role("combobox").fill("acme-client")
    palette.get_by_role("option", name=re.compile("^acme-client")).first.click()
    expect(page).to_have_url(re.compile(r"/certificates\?cert="))
    expect(sheet(page).get_by_text("acme-client").first).to_be_visible()


def test_add_edit_and_delete_a_provisioner(page):
    sign_in(page, "/provisioners")
    page.get_by_role("button", name="Add provisioner").click()
    dialog = page.get_by_role("dialog", name="Add provisioner")
    dialog.get_by_label("Name", exact=True).fill("e2e-ui-acme")
    dialog.get_by_role("button", name="Add provisioner").click()
    expect(page.get_by_role("heading", name="e2e-ui-acme", exact=True)).to_be_visible()

    page.get_by_role("checkbox", name=re.compile("dns-01")).check()
    page.get_by_label("Maximum").fill("48h")
    expect(page.get_by_role("status").filter(has_text="2 unsaved changes")).to_be_visible()
    page.get_by_role("button", name="Save changes").click()
    expect(page.get_by_text("Saved. Applied live")).to_be_visible()
    # What step-ca now has
    page.reload()
    expect(page.get_by_label("Maximum")).to_have_value("48h")
    expect(page.get_by_role("checkbox", name=re.compile("dns-01"))).to_be_checked()

    page.get_by_role("button", name="Delete…").click()
    page.get_by_role("alertdialog").get_by_role("button", name="Delete provisioner").click()
    expect(page.get_by_role("heading", name="Provisioners", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="e2e-ui-acme")).to_have_count(0)
    assert page.problems == []
