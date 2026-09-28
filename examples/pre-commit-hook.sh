#!/bin/sh
# .git/hooks/pre-push - fast local gate.
exec argus scan . --severity medium --fail-on medium --color never
