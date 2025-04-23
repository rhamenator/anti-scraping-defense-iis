-- anti_scrape/db/init_markov.sql (Placeholder Schema)
-- Basic schema for PostgreSQL Markov chain storage

-- Table to store unique words/tokens
CREATE TABLE IF NOT EXISTS markov_words (
    id SERIAL PRIMARY KEY,
    word TEXT UNIQUE NOT NULL
);

-- Create index for faster word lookup
CREATE INDEX IF NOT EXISTS idx_markov_words_word ON markov_words (word);

-- Insert the empty string as a special token (ID 1 if table is empty)
INSERT INTO markov_words (word) VALUES ('') ON CONFLICT (word) DO NOTHING;

-- Table to store sequences (word1_id -> word2_id -> next_word_id) and frequency
CREATE TABLE IF NOT EXISTS markov_sequences (
    p1 INT NOT NULL REFERENCES markov_words(id),
    p2 INT NOT NULL REFERENCES markov_words(id),
    next_id INT NOT NULL REFERENCES markov_words(id),
    freq INT DEFAULT 1 NOT NULL,
    -- Constraint to ensure combination of p1, p2, next_id is unique
    CONSTRAINT uq_sequence UNIQUE (p1, p2, next_id)
);

-- Index for fast lookup of next possible words based on previous two
CREATE INDEX IF NOT EXISTS idx_markov_sequences_prev ON markov_sequences (p1, p2);

-- Optional: Index for frequency-based lookups if needed
CREATE INDEX IF NOT EXISTS idx_markov_sequences_freq ON markov_sequences (p1, p2, freq DESC);

-- Example of how the training script would insert/update:
-- INSERT INTO markov_sequences (p1, p2, next_id, freq)
-- VALUES (%s, %s, %s, 1)
-- ON CONFLICT (p1, p2, next_id) DO UPDATE SET freq = markov_sequences.freq + 1;