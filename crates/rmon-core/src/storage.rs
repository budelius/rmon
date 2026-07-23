use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::Connection;

use std::str::FromStr;

use crate::model::{GpuSource, ProcessSample, Snapshot, SystemMetrics};

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self { conn })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                ppid INTEGER,
                name TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                gpu_percent REAL NOT NULL,
                gpu_source TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
            CREATE INDEX IF NOT EXISTS idx_samples_pid ON samples(pid);
            CREATE INDEX IF NOT EXISTS idx_samples_name ON samples(name);
            "#,
        )?;
        Ok(())
    }

    /// Persists every process sample in a snapshot as one row each, inside
    /// a single transaction.
    pub fn insert_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO samples (ts, pid, ppid, name, cpu_percent, gpu_percent, gpu_source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            let ts = snapshot.timestamp.timestamp_millis();
            for p in &snapshot.processes {
                stmt.execute(rusqlite::params![
                    ts,
                    p.pid,
                    p.ppid,
                    p.name,
                    p.cpu_percent,
                    p.gpu_percent,
                    p.gpu_source.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// All samples with `ts` in `[since, until]`, ordered oldest first.
    pub fn query_range(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<Vec<Snapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, pid, ppid, name, cpu_percent, gpu_percent, gpu_source
             FROM samples WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts ASC",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![since.timestamp_millis(), until.timestamp_millis()],
            |row| {
                let ts_millis: i64 = row.get(0)?;
                let gpu_source: String = row.get(6)?;
                Ok((
                    ts_millis,
                    ProcessSample {
                        pid: row.get(1)?,
                        ppid: row.get(2)?,
                        name: row.get(3)?,
                        cpu_percent: row.get(4)?,
                        gpu_percent: row.get(5)?,
                        gpu_source: GpuSource::from_str(&gpu_source).unwrap(),
                    },
                ))
            },
        )?;

        let mut snapshots: Vec<Snapshot> = Vec::new();
        for row in rows {
            let (ts_millis, sample) = row?;
            match snapshots.last_mut() {
                Some(last) if last.timestamp.timestamp_millis() == ts_millis => {
                    last.processes.push(sample);
                }
                _ => {
                    let timestamp = DateTime::from_timestamp_millis(ts_millis)
                        .unwrap_or_else(Utc::now);
                    snapshots.push(Snapshot {
                        timestamp,
                        processes: vec![sample],
                        system: SystemMetrics::default(),
                    });
                }
            }
        }
        Ok(snapshots)
    }

    /// CPU/GPU history for a single process name across `[since, until]`,
    /// as `(timestamp, cpu_percent, gpu_percent)` tuples ordered oldest first.
    pub fn query_process_history(
        &self,
        name: &str,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<Vec<(DateTime<Utc>, f32, f32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, cpu_percent, gpu_percent FROM samples
             WHERE name = ?1 AND ts BETWEEN ?2 AND ?3 ORDER BY ts ASC",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![name, since.timestamp_millis(), until.timestamp_millis()],
            |row| {
                let ts_millis: i64 = row.get(0)?;
                Ok((ts_millis, row.get::<_, f32>(1)?, row.get::<_, f32>(2)?))
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            let (ts_millis, cpu, gpu) = row?;
            let ts = DateTime::from_timestamp_millis(ts_millis).unwrap_or_else(Utc::now);
            out.push((ts, cpu, gpu));
        }
        Ok(out)
    }

    /// Deletes samples older than `before`. Returns the number of rows removed.
    pub fn prune_before(&self, before: DateTime<Utc>) -> Result<usize> {
        let n = self
            .conn
            .execute(
                "DELETE FROM samples WHERE ts < ?1",
                rusqlite::params![before.timestamp_millis()],
            )?;
        Ok(n)
    }
}
