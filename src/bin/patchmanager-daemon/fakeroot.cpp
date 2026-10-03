
#include <QObject>
#include <QDir>

#include <QDebug>

#include "locations.h"
#include "fakeroot.h"

static const QString s_patchmanagerCacheRoot = QStringLiteral("/tmp/patchmanager");

void PatchManagerFakeroot::clear()
{
    qDebug() << Q_FUNC_INFO;

    eraseRecursively(rootDir());
    qDebug() << Q_FUNC_INFO << "Directory" << rootDir() << "is cleansed (bool):" <<
    QDir::root().rmpath(rootDir());

    qDebug() << Q_FUNC_INFO << "Directory" << PATCHES_ADDITIONAL_DIR << "is cleansed (bool):" <<
    QDir(PATCHES_ADDITIONAL_DIR).removeRecursively();

    qDebug() << Q_FUNC_INFO << "Creating a clean cache directory (bool):" <<
    QDir::root().mkpath(rootDir());
}

void PatchManagerFakeroot::eraseRecursively(const QString &path)
{
    qDebug() << Q_FUNC_INFO << path;

    QDir cacheDir(path);
    for (const QFileInfo &info : cacheDir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot, QDir::DirsLast)) {
        if (info.isDir() && !info.isSymLink()) {
            eraseRecursively(info.absoluteFilePath());
            qDebug() << Q_FUNC_INFO << "Directory" << info.absoluteFilePath() << "is empty" <<
            QDir::root().rmpath(info.absoluteFilePath());
        } else if (info.isFile() || info.isSymLink()) {
            QFile::remove(info.absoluteFilePath());
        }
    }
}

bool PatchManagerFakeroot::checkIsFakeLinked(const QString &path)
{
    qDebug() << Q_FUNC_INFO << path;
    const QStringList parts = path.split(QDir::separator(), QString::SkipEmptyParts);
    QDir trial = QDir::root();
    for (const QString &part : parts) {
        if (trial.cd(part)) {
            const QFileInfo fi(trial.absolutePath());
            if (fi.isSymLink() && fi.symLinkTarget().startsWith(rootDir())) {
                qDebug() << Q_FUNC_INFO << path << "already has a faking symlink" << trial.absolutePath();
                return true;
            }
            continue;
        }
    }
    return false;
}

bool PatchManagerFakeroot::tryToLinkFakeParent(const QString &path)
{
    qDebug() << Q_FUNC_INFO << path;
    const QStringList parts = path.split(QDir::separator(), QString::SkipEmptyParts);
    QDir trial = QDir::root();
    for (const QString &part : parts) {
        if (trial.cd(part)) {
            const QFileInfo fi(trial.absolutePath());
            if (fi.isSymLink() && fi.symLinkTarget().startsWith(rootDir())) {
                qDebug() << Q_FUNC_INFO << path << "already has a faking symlink" << trial.absolutePath();
                return true;
            }
            continue;
        }
        const QString realPath = QStringLiteral("%1/%2").arg(trial.absolutePath(), part);
        const QString fakePath = QStringLiteral("%1%2").arg(rootDir(), realPath);
        bool link_ret = QFile::link(fakePath, realPath);
        qDebug() << Q_FUNC_INFO << "Symlinking" << realPath << "to" << fakePath << link_ret;
        return true;
    }
    return false;
}

bool PatchManagerFakeroot::tryToUnlinkFakeParent(const QString &path)
{
    qDebug() << Q_FUNC_INFO << path;
    const QStringList parts = path.split(QDir::separator(), QString::SkipEmptyParts);
    QDir trial = QDir::root();
    for (const QString &part : parts) {
        if (!trial.cd(part)) {
            qWarning() << Q_FUNC_INFO << "Failed when trying to change (cd) from directory" << trial.absolutePath() << "to" << part;
            return false;
        }
        const QFileInfo fi(trial.absolutePath());
        if (fi.isSymLink() && fi.symLinkTarget().startsWith(rootDir())) {
            bool remove_ret = QFile::remove(trial.absolutePath());
            qDebug() << Q_FUNC_INFO << "Removing" << trial.absolutePath() << remove_ret;
            return true;
        }
    }
    return false;
}


QString PatchManagerFakeroot::rootDir()
{
    return s_patchmanagerCacheRoot;
}
