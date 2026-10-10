use crate::hash::{HashAlgorithm, Hasher};
use crate::pe::page_hashes::{hash_pages, plan, terminator};
use crate::pe::{Error, PeFile};
use std::thread;

/// Result of [`digests`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// Authenticode digest for each requested algorithm, in the same order.
    pub file: Vec<Vec<u8>>,
    /// Page hash table, if requested.
    pub page_hashes: Option<Vec<u8>>,
}

/// Computes the Authenticode digest of the file for each of `algorithms` and, if asked, the
/// page hash table, in one call that reads the file once (through the page cache) and
/// uses all the cores.
///
/// Each file digest runs on its own thread (a hash of one stream cannot be split), and the
/// pages are divided between the remaining cores (at least one thread). The results are
/// byte-identical to [`authenticode_digest`](crate::pe::authenticode_digest) and
/// [`page_hashes`](crate::pe::page_hashes), and so are the errors.
pub fn digests(
    data: &[u8],
    algorithms: &[HashAlgorithm],
    page_hashes: Option<HashAlgorithm>,
) -> Result<Digests, Error> {
    let pe = PeFile::parse(data)?;
    let hashed = if algorithms.is_empty() {
        None
    } else {
        Some(pe.hashed_ranges()?)
    };
    let pages = match page_hashes {
        Some(algorithm) => Some((algorithm, plan(&pe)?)),
        None => None,
    };

    let cores = thread::available_parallelism().map_or(1, |n| n.get());
    let workers = cores.saturating_sub(algorithms.len()).max(1);
    let pe = &pe;

    Ok(thread::scope(|scope| {
        let file_threads: Vec<_> = hashed
            .iter()
            .flat_map(|hashed| {
                algorithms.iter().map(move |&algorithm| {
                    scope.spawn(move || {
                        let mut hasher = Hasher::new(algorithm);
                        for r in &hashed.ranges {
                            hasher.update(&pe.data[r.clone()]);
                        }
                        hasher.update(&[0u8; 8][..hashed.padding]);
                        hasher.finalize()
                    })
                })
            })
            .collect();

        let page_threads = pages.as_ref().map(|(algorithm, plan)| {
            let total = plan.len();
            let chunk = total.div_ceil(workers.min(total));
            let threads: Vec<_> = (0..total)
                .step_by(chunk)
                .map(|first| {
                    let range = first..(first + chunk).min(total);
                    scope.spawn(move || hash_pages(pe, plan, *algorithm, range))
                })
                .collect();
            (*algorithm, plan, threads)
        });

        let join = |t: thread::ScopedJoinHandle<'_, Vec<u8>>| {
            t.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
        };
        let file = file_threads.into_iter().map(join).collect();
        let page_hashes = page_threads.map(|(algorithm, plan, threads)| {
            let mut table: Vec<u8> = threads.into_iter().flat_map(join).collect();
            table.extend_from_slice(&terminator(plan, algorithm));
            table
        });
        Digests { file, page_hashes }
    }))
}
