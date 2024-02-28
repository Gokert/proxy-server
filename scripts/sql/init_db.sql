DROP TABLE IF EXISTS requests;
CREATE TABLE IF NOT EXISTS requests (
    id        serial NOT NULL PRIMARY KEY,
    method    text NOT NULL,
    scheme    text NOT NULL,
    host      text NOT NULL,
    path      text NOT NULL,
    headers   jsonb NOT NULL,
    params   jsonb NOT NULL,
    body      text NOT NULL
);

DROP TABLE IF EXISTS responses;
CREATE TABLE IF NOT EXISTS responses (
    id  serial NOT NULL PRIMARY KEY,
    request_id  integer NOT NULL,
    code integer NOT NULL,
    message text NOT NULL,
    headers   jsonb NOT NULL,
    body      text NOT NULL,

    FOREIGN KEY (request_id) REFERENCES requests(id)
);