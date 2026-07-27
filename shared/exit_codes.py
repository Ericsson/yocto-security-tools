# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Exit codes for CVE tools.

Single source of truth for exit codes shared between cve_corrector and cve_agent.
"""

# Corrector exit codes (0-12)
EXIT_SUCCESS = 0            # Workflow completed successfully
EXIT_CONFLICT = 1           # Conflict detected (manual resolution required)
EXIT_CHECKOUT_ERROR = 2     # Checkout/version error
EXIT_PTEST_ERROR = 3        # Post-patch ptest failure
EXIT_BUILD_ERROR = 4        # Post-patch build failure
EXIT_PATCH_ERROR = 5        # Patch generation/application error
EXIT_METADATA_ERROR = 6     # Metadata/configuration error
EXIT_GIT_ERROR = 7          # Git operation error
EXIT_PTEST_PREEXISTING = 8  # Pre-patch ptest already failing
EXIT_DEVTOOL_ERROR = 9      # Devtool operation error
EXIT_BUILD_PREEXISTING = 10 # Pre-patch build already failing
EXIT_ALREADY_APPLIED = 11   # CVE fix already present in source tree
EXIT_NOT_APPLICABLE = 12    # Vulnerable code not present in recipe version
EXIT_IGNORED_BY_STATUS = 16 # Recipe's CVE_STATUS marks this CVE as ignored/not-affected

# Agent exit codes (13-15)
EXIT_TRUST_DECLINED = 13    # User declined trust mode
EXIT_AGENT_ERROR = 14       # Internal agent error
EXIT_AI_TIMEOUT = 15        # AI session timed out
