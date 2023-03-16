# Match Okta User-Password

This repository contains a SQL query that helps detect if users' credentials are accidentally stored in Okta audit logs. The SQL query matches failed login attempts with a password pattern to subsequent successful login attempts. The blog post that inspired this SQL code highlights the risk of inadvertently storing passwords due to user error when passwords are mistakenly entered into the username field. Attackers can then try to bypass MFA by reading the Okta audit logs from the SIEM product the organization uses. Users are encouraged to be mindful of their login credentials and to ensure that passwords are entered correctly in the right field.

##### link to blogpost


## SQL Query

The SQL query included in this repository uses a common table expression (CTE) to define several subqueries that filter and group Okta authentication data. The final subquery joins the success and passw subqueries based on several columns to identify failed attempts with passwords in the username field, that meet specific criteria. Specifically, the query filters for failed logins where the username is at least 8 characters long, does not contain "@domain" or ".com", does not start with "0oa", and meets the regex pattern of containing at least one lowercase letter, one uppercase letter, and one digit.
The resulting dataset can be used to better understand the security posture of your organization and take proactive measures to protect against potential threats.


```SQL

WITH t0 AS (
select 
 user_email
, TO_DATE(published) as date_day
, date_part('HOUR', published) as date_hour
, get_json_object(debugContext, "$.debugData.deviceFingerprint") as deviceFingerprint
, src_ip
, src_useragent
, event_type
from 
okta.okta_df
Where user_email <> 'system@okta.com'
)

, success as (
 SELECT
 user_email
, date_day
, date_hour
, deviceFingerprint
, src_ip
, src_useragent
FROM t0
WHERE event_type = 'core.user_auth.login_success'
)

, passw as (
SELECT
 user_email as password
, date_day
, date_hour
, deviceFingerprint
, src_ip
, src_useragent
FROM t0
WHERE event_type = 'core.user_auth.login_failed'
and length(user_email) >= 8
and user_email NOT LIKE '%@domain%'
and user_email NOT LIKE '%@domain%'
and user_email NOT LIKE '%.com'
and user_email NOT LIKE '0oa%'
and user_email RLIKE "(?=.*\d)(?=.*[a-z])(?=.*[A-Z])"
)

, joined as (
select 
*
from success as s
JOIN passw as p using (date_day, date_hour, deviceFingerprint, src_ip, src_useragent)
ON p.date_day = s.date_day AND p.date_hour = s.date_hour AND p.src_ip = s.src_ip AND p.src_useragent = s.src_useragent AND p.deviceFingerprint = s.deviceFingerprint
)
```




