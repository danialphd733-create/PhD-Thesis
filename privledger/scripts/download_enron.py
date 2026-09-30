"""Download official CMU release and safely extract the three thesis custodians."""
import argparse
import hashlib
import json
import pathlib
import tarfile
import urllib.request

URL = 'https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz'
CUSTODIANS = {'lay-k', 'skilling-j', 'kaminski-v'}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--destination', default='data/raw/enron')
    args = p.parse_args()
    dest = pathlib.Path(args.destination).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / 'enron_mail_20150507.tar.gz'
    if not archive.exists():
        partial = archive.with_suffix('.part')
        print('Downloading official CMU Enron archive', flush=True)
        with urllib.request.urlopen(URL, timeout=90) as src, partial.open('wb') as out:
            total = 0
            while block := src.read(1024*1024):
                out.write(block)
                total += len(block)
                if total % (50*1024*1024) == 0:
                    print(f'Downloaded {total//1024//1024} MiB', flush=True)
        partial.replace(archive)
    digest = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    count = 0
    with tarfile.open(archive, 'r|gz') as tf:
        for member in tf:
            parts = pathlib.PurePosixPath(member.name).parts
            if len(parts) < 3 or parts[0] != 'maildir' or parts[1] not in CUSTODIANS or not member.isfile():
                continue
            target = dest.joinpath(*parts).resolve()
            if not target.is_relative_to(dest) or any(p in ('..', '.') for p in parts):
                raise ValueError('Unsafe archive path')
            target.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(member) as src, target.open('wb') as out:
                out.write(src.read())
            count += 1
    (dest/'download_provenance.json').write_text(json.dumps({'source': URL, 'sha256': digest, 'files': count, 'custodians': sorted(CUSTODIANS), 'attachments': 'CMU release excludes attachments'}, indent=2))
    print(f'Extracted {count} messages from three custodians', flush=True)

if __name__ == '__main__':
    main()
