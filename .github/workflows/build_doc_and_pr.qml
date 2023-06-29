name: Build generated documentation on documentation branches

on:
  push:
    branches:
      - documentation

jobs:
  build:
    runs-on: ubuntu-22.04
    env:
      SEGMENT_DOWNLOAD_TIMEOUT_MINS: 1
    steps:
    - name: Checkout
      uses: actions/checkout@v3

    - name: Build documentation
      run: |
        set -x
        mkdir -p output/
        export DEBIAN_FRONTEND=noninteractive
        apt-get -qq update
        apt-get -qq install git-core qdoc-qt5
        ./makedocs

    - name: Create Pull Request
      uses: peter-evans/create-pull-request@v5
      with:
        branch: build-docs/patch
        title: "Updated auto-generated Documentation"
        delete-branch: true
        draft: true
#      env:
#        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
