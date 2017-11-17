#!/bin/bash
VERSION=$1
BRANCH=$2
GIT_PREVIOUS_COMMIT=$3
GIT_COMMIT=$4

if [ $VERSION ]; then
    VERSION="-$VERSION"
fi

if [ "$GIT_PREVIOUS_COMMIT" == "$GIT_COMMIT" ]; then
        RANGE="$GIT_PREVIOUS_COMMIT^..$GIT_COMMIT"
else
        RANGE="$GIT_PREVIOUS_COMMIT..$GIT_COMMIT"
fi

TRAILER_LINE=" -- Michal Gacek <gaco@cs.com>  `date -R`"
LAST_VERSION=`head -n 1 debian/changelog`
CHANGELOG_MSG=`git log --no-merges --branches=$BRANCH --format="  * [%h] - %aN: %s" $RANGE`


echo -e "$LAST_VERSION\n\n$CHANGELOG_MSG\n\n$TRAILER_LINE\n\n$(cat debian/changelog)\n" > debian/changelog

sed -i "0,/)/ s/)/$VERSION)/" debian/changelog


/usr/bin/mk-build-deps -t 'apt-get -y' --install debian/control
dpkg-buildpackage -us -uc
