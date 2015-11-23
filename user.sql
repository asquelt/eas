DROP TABLE USER;

CREATE TABLE USER
(
	id			INTEGER PRIMARY KEY AUTOINCREMENT,
	real_uid		INTEGER NOT NULL,
	real_gid		INTEGER NOT NULL,
	effective_uid		INTEGER NOT NULL,
	effective_gid		INTEGER NOT NULL,
	original_uid		INTEGER NOT NULL,
	original_gid		INTEGER NOT NULL,
	port			INTEGER NOT NULL,
	duration		INTEGER NOT NULL,
	real_pw_name		VARCHAR(63) NOT NULL,
	real_gr_name		VARCHAR(63) NOT NULL,
	effective_pw_name	VARCHAR(63) NOT NULL,
	effective_gr_name	VARCHAR(63) NOT NULL,
	original_pr_name	VARCHAR(63) NOT NULL,
	terminal		VARCHAR(63) NOT NULL,
	ip			VARCHAR(16) NOT NULL,
	status			VARCHAR(63) NOT NULL,
	stype			VARCHAR(63) NOT NULL,
	method			VARCHAR(63) NOT NULL,
	cipher			VARCHAR(63) NOT NULL,
	file_session		VARCHAR(63),
	hash_session		VARCHAR(63),
	file_timing		VARCHAR(63),
	hash_timing		VARCHAR(63),
	file_input		VARCHAR(63),
	hash_input		VARCHAR(63),
	dns			VARCHAR(127),
	remote_command		VARCHAR(255),
	created			DATETIME,
	modified		DATETIME
);

CREATE TRIGGER INSERT_USER_CREATED AFTER INSERT ON USER
BEGIN
	UPDATE USER SET created = DATETIME('now') WHERE id = new.id;
	UPDATE USER SET modified = DATETIME('now') WHERE id = new.id;
END;

CREATE TRIGGER INSERT_USER_MODIFIED AFTER UPDATE ON USER
BEGIN
	UPDATE USER SET modified = DATETIME('now') WHERE id = new.id;
END;
