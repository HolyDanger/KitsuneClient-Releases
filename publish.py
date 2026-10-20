"""GitHub-hosted runner: fetch only public ciphertext/distribution binaries."""
import concurrent.futures, hashlib, json, pathlib, re, time, urllib.request

ORIGIN = 'https://kitsune-client-downloads.siestaguard.workers.dev'
data = json.loads(pathlib.Path('release-input.json').read_text())
assert re.fullmatch(r'r[0-9]+-[a-z0-9-]+', data['tag'])
assert len(data['assets']) == 3
out = pathlib.Path('dist'); out.mkdir(exist_ok=True)

def fetch(path, size):
    assert path.startswith(('/downloads/', '/artifacts/')) and '..' not in path
    for attempt in range(5):
        try:
            with urllib.request.urlopen(ORIGIN + path, timeout=30) as response:
                assert response.status == 200
                body = response.read(size + 1)
                assert len(body) == size
                return body
        except Exception:
            if attempt == 4: raise
            time.sleep(attempt + 1)

for asset in data['assets']:
    name, size, digest = asset['name'], asset['size'], asset['sha256']
    assert re.fullmatch(r'[A-Za-z0-9_.-]+', name) and re.fullmatch(r'[a-f0-9]{64}', digest)
    assert 0 < size < 200_000_000
    target = out / name
    if 'parts' in asset:
        chunk = asset['chunkSize']; assert chunk in (8192, 16384, 24000000)
        count = (size + chunk - 1) // chunk
        def part(i):
            body = fetch(asset['parts'] + f'{i:06d}.chunk', min(chunk, size-i*chunk))
            return i, body
        with target.open('wb') as stream:
            stream.truncate(size)
            with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
                pending = [pool.submit(part,i) for i in range(count)]
                for done in concurrent.futures.as_completed(pending):
                    i, body = done.result(); stream.seek(i*chunk); stream.write(body)
    else:
        target.write_bytes(fetch(asset['path'], size))
    assert target.stat().st_size == size
    assert hashlib.sha256(target.read_bytes()).hexdigest() == digest, name + ' digest rejected'
    print('Verified', name, size, flush=True)
(out / 'SHA256SUMS.txt').write_text(''.join(a['sha256']+'  '+a['name']+'\n' for a in data['assets']))