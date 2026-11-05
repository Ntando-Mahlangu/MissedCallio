-- SMS opt-out suppression list (TCPA / STOP keyword compliance)
-- Callers who reply STOP / QUIT / END / UNSUBSCRIBE are recorded here.
-- sendAppointmentConfirmation and sendAppointmentReminder check this table
-- before sending any outbound SMS to a caller number.

CREATE TABLE IF NOT EXISTS sms_suppressions (
  phone        TEXT PRIMARY KEY,          -- E.164 normalized phone number
  suppressed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index already covered by PRIMARY KEY on phone.
-- No foreign key to businesses: suppression is caller-side, not tenant-side.
