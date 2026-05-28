#!/usr/bin/env bash
# ClearCutt Transient Enterprise Proxy Credential Broker
# Author: Eddie Northcutt
# Zero-configuration enterprise package management gateway router

# Set isolation workspace path
AUTH_CACHE_DIR="$PWD/.nix-enterprise-auth-cache"

# Helper for secure environment setup
init_credential_broker() {
  # Intercept required environment variables
  if [[ -z "$ENTERPRISE_MIRROR_URL" ]] || [[ -z "$ENTERPRISE_MIRROR_USER" ]] || [[ -z "$ENTERPRISE_MIRROR_TOKEN" ]]; then
    echo -e "\033[1;33m[ClearCutt Broker]\033[0m Enterprise mirror credentials not fully set. Bypassing broker setup."
    echo -e "  To activate, define: \033[36mENTERPRISE_MIRROR_URL\033[0m, \033[36mENTERPRISE_MIRROR_USER\033[0m, and \033[36mENTERPRISE_MIRROR_TOKEN\033[0m"
    return 0
  fi

  echo -e "\033[1;32m[ClearCutt Broker]\033[0m Enterprise credentials detected. Materializing secure proxy routes..."

  # Create isolated credentials storage workspace
  mkdir -p "$AUTH_CACHE_DIR"
  chmod 700 "$AUTH_CACHE_DIR"

  # Ensure git ignore-isolation
  if [[ -d ".git" ]]; then
    mkdir -p .git/info
    if ! grep -q ".nix-enterprise-auth-cache" .git/info/exclude 2>/dev/null; then
      echo ".nix-enterprise-auth-cache/" >> .git/info/exclude
      echo -e "\033[1;32m[ClearCutt Broker]\033[0m Added .nix-enterprise-auth-cache/ to local git exclusion list."
    fi
  fi

  # ----------------------------------------------------
  # 1. NPM Authentication Broker (.npmrc)
  # ----------------------------------------------------
  # Extract host and relative path for scoped auth config
  local proto_removed
  proto_removed=$(echo "$ENTERPRISE_MIRROR_URL" | sed -E 's|^https?:||')
  local registry_path
  registry_path=$(echo "$proto_removed" | sed -E 's|/?$|/|') # Ensure trailing slash

  # npm's legacy basic-auth fields expect `_password` to be the base64 of the
  # password ALONE (it pairs with the plaintext `username`); the combined
  # base64("user:password") form belongs to the `_auth` field. Emit both the
  # bearer token (`_authToken`, for token registries) and a correct legacy
  # basic-auth triple so Nexus/Artifactory in either mode authenticates.
  local base64_password
  base64_password=$(printf '%s' "${ENTERPRISE_MIRROR_TOKEN}" | base64)
  local base64_auth
  base64_auth=$(printf '%s' "${ENTERPRISE_MIRROR_USER}:${ENTERPRISE_MIRROR_TOKEN}" | base64)

  # Write token and user-pass variants to cover all NPM/Yarn client types
  cat <<EOF > "$AUTH_CACHE_DIR/.npmrc"
registry=${ENTERPRISE_MIRROR_URL}
${registry_path}:_authToken=${ENTERPRISE_MIRROR_TOKEN}
${registry_path}:username=${ENTERPRISE_MIRROR_USER}
${registry_path}:_password=${base64_password}
${registry_path}:_auth=${base64_auth}
${registry_path}:always-auth=true
EOF
  chmod 600 "$AUTH_CACHE_DIR/.npmrc"

  # Route npm tool dynamically to the memory-cached auth file
  export NPM_CONFIG_USERCONFIG="$AUTH_CACHE_DIR/.npmrc"
  echo -e "  \033[32m✔\033[0m NPM auth routed -> \033[36m\$NPM_CONFIG_USERCONFIG\033[0m"

  # ----------------------------------------------------
  # 2. Python Pip Broker (.netrc)
  # ----------------------------------------------------
  local hostname
  hostname=$(echo "$ENTERPRISE_MIRROR_URL" | sed -E 's|^https?://([^/]+).*|\1|')

  cat <<EOF > "$AUTH_CACHE_DIR/.netrc"
machine ${hostname}
login ${ENTERPRISE_MIRROR_USER}
password ${ENTERPRISE_MIRROR_TOKEN}
EOF
  chmod 600 "$AUTH_CACHE_DIR/.netrc"

  # Set environment variables for Pip and generic netrc consumers
  export NETRC="$AUTH_CACHE_DIR/.netrc"
  export PIP_INDEX_URL="$ENTERPRISE_MIRROR_URL"
  echo -e "  \033[32m✔\033[0m Python Pip routed -> \033[36m\$NETRC\033[0m & \033[36m\$PIP_INDEX_URL\033[0m"

  # ----------------------------------------------------
  # 3. Java Maven & Gradle Broker (settings.xml & init.gradle)
  # ----------------------------------------------------
  # Compile ephemeral Maven settings.xml
  cat <<EOF > "$AUTH_CACHE_DIR/settings.xml"
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <id>enterprise-mirror</id>
      <username>${ENTERPRISE_MIRROR_USER}</username>
      <password>${ENTERPRISE_MIRROR_TOKEN}</password>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>enterprise-mirror</id>
      <name>Enterprise Authenticated Mirror</name>
      <url>${ENTERPRISE_MIRROR_URL}</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
EOF
  chmod 600 "$AUTH_CACHE_DIR/settings.xml"

  # Setup alias for Maven shell execution
  alias mvn="mvn -s $AUTH_CACHE_DIR/settings.xml"
  
  # Inject Gradle configuration overlay
  cat <<EOF > "$AUTH_CACHE_DIR/init.gradle"
allprojects {
    repositories {
        all { ArtifactRepository repo ->
            if (repo instanceof MavenArtifactRepository) {
                repo.url = uri("${ENTERPRISE_MIRROR_URL}")
                repo.credentials {
                    username = "${ENTERPRISE_MIRROR_USER}"
                    password = "${ENTERPRISE_MIRROR_TOKEN}"
                }
            }
        }
    }
}
EOF
  chmod 600 "$AUTH_CACHE_DIR/init.gradle"

  # Export gradle initialization parameter
  export GRADLE_OPTS="-I $AUTH_CACHE_DIR/init.gradle"
  echo -e "  \033[32m✔\033[0m Java Maven/Gradle routed -> \033[36msettings.xml\033[0m (via alias) & \033[36m\$GRADLE_OPTS\033[0m"

  # ----------------------------------------------------
  # 4. Cleanup and Exit Guardrails
  # ----------------------------------------------------
  # Register trap to clean up workspace session environment variables
  cleanup_credential_broker() {
    echo -e "\n\033[1;31m[ClearCutt Broker]\033[0m Cleaning session environment hooks and wiping active memory cache..."
    unset NPM_CONFIG_USERCONFIG
    unset NETRC
    unset PIP_INDEX_URL
    unset GRADLE_OPTS
    unalias mvn 2>/dev/null || true
    
    # Delete the temporary session cache directory
    # Note: Secure dd overwriting represents security theater on modern filesystems (COW, SSDs, journaling)
    # as physical flash sectors are not guaranteed to be zeroed immediately.
    if [[ -d "$AUTH_CACHE_DIR" ]]; then
      rm -rf "$AUTH_CACHE_DIR"
    fi
    echo -e "\033[1;32m[ClearCutt Broker]\033[0m Session credentials destroyed. Guardrails verified."
  }

  # Register exit traps to automatically trigger cleanup upon shell exit or cancellation
  trap cleanup_credential_broker EXIT INT TERM
}

# Run setup
init_credential_broker
