# app/email_service.py
#
# DEF-025 FIX / DEAD-CODE REMOVAL:
# This module previously contained a DUPLICATE reviewer-notification function
# that hardcoded a 72-hour token expiry and ignored the admin-configured
# "reviewer_link_expiry_hours" value. That stale copy is the likely source of
# DEF-025 (tokenized link not expiring per the configured hours).
#
# The single source of truth for notification emails and tokenised links is
# now app/workflow.py, which:
#   * reads the configured expiry via _get_expiry_hours(), and
#   * generates the JWT through app.auth.generate_access_token(expires_hours=...)
#     so the token's exp claim always reflects the Admin configuration.
#
# Nothing imports this module. It is intentionally left empty to prevent the
# old hardcoded-expiry path from ever being reintroduced.
