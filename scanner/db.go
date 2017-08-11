package scanner

import (
	"database/sql"
	"strings"

	log "github.com/Sirupsen/logrus"
)

// ScanDb represents an SQL database along with the table name used for queries
type ScanDb struct {
	db        *sql.DB
	tableName string
}

// SqliteDb returns a ScanDb with an underlying SQLite database
func SqliteDb(dbFile, tableName string) (*ScanDb, error) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}
	return &ScanDb{db, tableName}, nil
}

// PostgresDb returns a ScanDb with an underlying PostgreSQL database
func PostgresDb(config, tableName string) (*ScanDb, error) {
	db, err := sql.Open("postgres", config)
	if err != nil {
		return nil, err
	}
	return &ScanDb{db, tableName}, nil
}

// QueryChecksum returns true if the checksum for the IP, port matches
func (sdb *ScanDb) QueryChecksum(ipPort string, checksum string) bool {
	split := strings.Split(ipPort, ":")
	ip := split[0]
	port := split[1]

	stmt, err := sdb.db.Prepare("SELECT COUNT(*) FROM " + sdb.tableName + " WHERE ip = $1 AND port = $2 AND pubkey_hash = $3")
	if err != nil {
		log.Fatal("Could not prepare SELECT statement: ", err)
	}
	defer stmt.Close()
	var count int
	err = stmt.QueryRow(ip, port, checksum).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	return count > 0
}

// Close closes the underlying database connection
func (sdb *ScanDb) Close() {
	sdb.db.Close()
}
