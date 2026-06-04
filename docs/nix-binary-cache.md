# Declarative Nix Binary Cache via Cloudflare R2 & clearcutt.dev

This document provides complete instructions for establishing a high-performance, **zero-egress-fee** custom Nix binary cache for ClearCutt using Cloudflare R2 and your domain `clearcutt.dev`.

---

## Architecture Overview

```mermaid
graph LR
    CI[GitHub Actions CI] -- "1. Compiles & Signs" --> Sign[Nix Store Path]
    Sign -- "2. nix copy (S3 protocol)" --> R2[Cloudflare R2 Bucket]
    R2 -- "3. Serves via CDN Edge" --> Edge[nix-cache.clearcutt.dev]
    Edge -- "4. Fast Download (HTTPS)" --> Dev[Developer Laptop / Prod Server]
```

By placing Cloudflare’s CDN in front of an R2 bucket on `nix-cache.clearcutt.dev`, compiled Nix packages (even huge closures like LLVM, GCC, or custom JDKs) are distributed globally in milliseconds. Because R2 has **zero egress fees**, developers can pull gigabytes of caches daily without generating AWS-style bandwidth bills.

---

## Setup Guide

### Step 1: Create R2 Bucket & Configure Custom Domain
1. Log in to your **Cloudflare Dashboard**.
2. Navigate to **R2** in the left sidebar and click **Create Bucket**.
   * **Bucket Name:** `clearcutt-nix-cache`
3. Click on the newly created bucket, go to the **Settings** tab.
4. Scroll to **Public Access** -> **Custom Domains**.
5. Click **Connect Domain** and enter:
   * **Domain:** `nix-cache.clearcutt.dev`
6. Click **Continue**. Cloudflare will automatically configure the DNS records and provision a managed SSL certificate.

---

### Step 2: Generate Nix Cache Signing Keys
To prevent malicious or untampered packages from being downloaded into the cache, Nix requires all binary store paths to be signed.

Run the following command on your local machine to generate the cryptographic keypair:
```bash
nix-store --generate-binary-cache-key clearcutt-cache-1 cache-secret-key.pem cache-public-key.pem
```

* **Private Key File (`cache-secret-key.pem`):** Keep this extremely secure. You will save its contents as a GitHub Repository Secret.
* **Public Key File (`cache-public-key.pem`):** This is safe to publish. Developers will use it to verify downloads.

---

### Step 3: Configure GitHub Actions Secrets
In your GitHub repository (`northcutted/clearcutt`), navigate to **Settings** -> **Secrets and variables** -> **Actions** and add the following repository secrets:

1. `NIX_CACHE_SECRET_KEY`: The exact multiline contents of your `cache-secret-key.pem`.
2. `R2_ACCESS_KEY_ID`: Cloudflare R2 Access Key ID (generated under Cloudflare -> R2 -> Manage R2 API Tokens).
3. `R2_SECRET_ACCESS_KEY`: Cloudflare R2 Secret Access Key.
4. `CLOUDFLARE_ACCOUNT_ID`: Your 32-character Cloudflare Account ID (visible on the R2 homepage).
5. `CLOUDFLARE_ZONE_ID`: (Optional) Your 32-character Cloudflare Zone ID (visible on your domain's Overview homepage). Providing this is highly recommended as it avoids requiring the `CLOUDFLARE_API_TOKEN` to have account-wide `Zone:Zone:Read` lookup permissions.

---

### Step 4: Automate Uploads in CI/CD Workflow
Add this job step to your GitHub Actions workflows (e.g. `.github/workflows/pr-gate.yml` or `release.yml`) directly after the Nix build step to automatically push successful builds to the R2 cache:

```yaml
      - name: Copy Built Layers to Cloudflare R2 Cache
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ZONE_ID: ${{ secrets.CLOUDFLARE_ZONE_ID }}
        run: |
          # 1. Temporarily write the private signing key
          printf '%s\n' "${{ secrets.NIX_CACHE_SECRET_KEY }}" > secret-key.pem
          chmod 600 secret-key.pem
          
          # 2. Sign and copy the compiled output to the R2 bucket using custom endpoint.
          # The S3 store's `secret-key` setting signs generated narinfo files.
          OUT_PATH=$(nix path-info --accept-flake-config .#coreLTS-slim)
          nix store sign --recursive --key-file secret-key.pem "$OUT_PATH"
          STORE_HASH="${OUT_PATH#/nix/store/}"
          STORE_HASH="${STORE_HASH%%-*}"
          NARINFO_KEY="${STORE_HASH}.narinfo"
          R2_ENDPOINT="https://${{ secrets.CLOUDFLARE_ACCOUNT_ID }}.r2.cloudflarestorage.com"
          aws --endpoint-url "$R2_ENDPOINT" s3 rm "s3://clearcutt-nix-cache/${NARINFO_KEY}" || true
          nix copy --accept-flake-config --refresh \
            --option narinfo-cache-positive-ttl 0 \
            --option narinfo-cache-negative-ttl 0 \
            --to "s3://clearcutt-nix-cache?region=auto&endpoint=https://${{ secrets.CLOUDFLARE_ACCOUNT_ID }}.r2.cloudflarestorage.com&secret-key=$PWD/secret-key.pem" \
            "$OUT_PATH"

          # 3. Verify the origin object, then purge the public CDN narinfo if available.
          aws --endpoint-url "$R2_ENDPOINT" s3 cp "s3://clearcutt-nix-cache/${NARINFO_KEY}" - |
            grep '^Sig: clearcutt-cache-1:'
          # In production, purge https://nix-cache.clearcutt.dev/${NARINFO_KEY}
          # with CLOUDFLARE_API_TOKEN so edge nodes stop serving stale unsigned metadata.
            
          # 4. Clean up the private key
          rm secret-key.pem
```

---

### Step 5: Configure Clients (Developers & Servers)
To instruct developer laptops or deployment servers to download pre-compiled binaries from your R2 CDN cache, configure their `/etc/nix/nix.conf` (or NixOS config) to query `nix-cache.clearcutt.dev` before compiling from scratch.

#### Developer Machine `/etc/nix/nix.conf` Configuration:
```conf
substituters = https://cache.nixos.org https://nix-cache.clearcutt.dev
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= clearcutt-cache-1:YOUR_PUBLIC_KEY_CONTENT_HERE
```

Replace `YOUR_PUBLIC_KEY_CONTENT_HERE` with the exact string from your `cache-public-key.pem` (e.g., `clearcutt-cache-1:aBcdEFg...`).

---

## Security Analysis

* **Zero Trust:** Even if your R2 bucket or Cloudflare account is compromised and a bad actor uploads modified packages, Nix will **reject them instantly** on developer laptops because the files will fail the cryptographic signature check of `clearcutt-cache-1`.
* **Zero Egress Fees:** Because Cloudflare R2 has zero bandwidth fees for downloading data out of R2 to the internet, you can distribute massive, compiler-heavy dependencies to unlimited CI runners or developers without incurring any cost.
