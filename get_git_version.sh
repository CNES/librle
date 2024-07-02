#! /bin/bash
#
# Will print variable assignement for version and release for 
# a package from git tag
# Author: Alexandre Chataignon

#
# Getting info
#

# First, test if git support --dirty flag
if [[ "$( git --version )" =~ "^git version 1.6.*" ]]; then
    CMD="git describe --tags --always --long --dirty"
else
    CMD="git describe --tags --always --long"
fi

# Run git describe
DESC=$( ${CMD} )
if [ $? -ne 0 -o -z "${DESC}" ]; then
    exit 1
fi

# Get branch information
BRANCH="$( git symbolic-ref HEAD 2> /dev/null)"
if [ -n "${BRANCH}" ]; then
    BRANCH="+$( basename ${BRANCH} )"
else
    BRANCH=$( git describe --all || grep heads || : )
    if [ -n "${BRANCH}" ]; then
        BRANCH="+$( basename ${BRANCH} )"
    fi
fi

# If BRANCH == DESC, it means we are not on a branch:
# this can happen if we have checkout'd a given SHA1.
# In such cases, append '+no_branch'
if [ "${BRANCH}" == "+${DESC}" ]; then
	BRANCH="+no_branch"
fi

# Parse it
#\1: Version, \2: NB commit, \3: useless, \4: SHA1, \5: dirty
REG="^([^-]*)-([0-9]+)(-|.)([a-h0-9]+)(-dirty)?$"

VERSION=$( echo "$DESC" | sed -r "s/$REG/\1/" )
RELEASE=$( echo "$DESC" | sed -r "s/$REG/\2.\4/" )
DIRTY=$( echo "$DESC" | sed -r "s/$REG/\5/" )

# If we are exactly on a tag, release is 1.el6
if [ "${RELEASE:0:1}" == "0" ]; then
    RELEASE="1"
    # Add el6 for centos
    if [ -f /etc/redhat-release ]; then
        RELEASE+=".el6"
    fi
else
    # We always add branch information when we are not exactly on a tag
    RELEASE+="${BRANCH}"
fi

# Debian dislike _ in version so sed it
if [ ! -f /etc/redhat-release ]; then
    RELEASE=`echo $RELEASE | sed s/_/-/g`
fi

if [ -n "${DIRTY}" ]; then
    # Add .dirty if it's the case
    RELEASE+=".dirty"
fi

# Force version from VERSION file to make it consistent accross all branches
THIS_DIR="$(dirname "$(readlink -e "$0")")"
VERSION=$( cat "$THIS_DIR"/VERSION )

#
# Output
#

if [ "$1" == "bash" ]; then
    echo "GIT_TAG_VERSION=${VERSION}"
    echo "GIT_TAG_RELEASE=${RELEASE}"
    echo "GIT_PACKAGE_VERSION=${VERSION}-${RELEASE}"
elif [ "$1" == "cmake" ]; then
    echo "${VERSION}-${RELEASE}"
elif [ "$1" == "sonar" ]; then 
    echo ${VERSION}
else
    echo "Usage: $0 cmake|bash|sonar"
    exit 1
fi
