-- CWE-522 remediation: add a BCrypt password hash column to user_system_data.
-- The password_hash column stores a one-way BCrypt hash of each user's password,
-- ensuring credentials are protected at rest. The plaintext password column is
-- intentionally preserved for the SQL-injection lesson (6a) that teaches students
-- to extract data via UNION-based injection; only lesson 6b (the answer-verification
-- endpoint) is updated to use BCrypt comparison.
ALTER TABLE user_system_data ADD COLUMN IF NOT EXISTS password_hash VARCHAR(60);
