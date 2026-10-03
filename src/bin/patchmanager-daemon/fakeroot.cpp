
#include <QObject>
#include <QDir>

#include <QDebug>

#include "locations.h"
#include "fakeroot.h"

#include "common/loggingcategory.h"
//Q_LOGGING_CATEGORY(patchmanagerDaemonLog, "patchmanager.daemon")

static const QString s_patchmanagerCacheRoot = QStringLiteral("/tmp/patchmanager");

void PatchManagerFakeroot::clear()
{
    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO;

    eraseRecursively(rootDir());
    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << "Directory" << rootDir() << "is cleansed (bool):" <<
    QDir::root().rmpath(rootDir());

    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << "Directory" << PATCHES_ADDITIONAL_DIR << "is cleansed (bool):" <<
    QDir(PATCHES_ADDITIONAL_DIR).removeRecursively();

    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << "Creating a clean cache directory (bool):" <<
    QDir::root().mkpath(rootDir());
}

void PatchManagerFakeroot::eraseRecursively(const QString &path)
{
    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << path;

    QDir cacheDir(path);
    for (const QFileInfo &info : cacheDir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot, QDir::DirsLast)) {
        if (info.isDir() && !info.isSymLink()) {
            eraseRecursively(info.absoluteFilePath());
            qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << "Directory" << info.absoluteFilePath() << "is empty" <<
            QDir::root().rmpath(info.absoluteFilePath());
        } else if (info.isFile() || info.isSymLink()) {
            QFile::remove(info.absoluteFilePath());
        }
    }
}

bool PatchManagerFakeroot::checkIsLinked(const QString &path)
{
    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << path;
    const QStringList parts = path.split(QDir::separator(), QString::SkipEmptyParts);
    QDir trial = QDir::root();
    for (const QString &part : parts) {
        if (trial.cd(part)) {
            const QFileInfo fi(trial.absolutePath());
            if (fi.isSymLink() && fi.symLinkTarget().startsWith(rootDir())) {
                qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << path << "already has a faking symlink" << trial.absolutePath();
                return true;
            }
            continue;
        }
    }
    return false;
}

bool PatchManagerFakeroot::tryToLinkParent(const QString &path)
{
    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << path;
    const QStringList parts = path.split(QDir::separator(), QString::SkipEmptyParts);
    QDir trial = QDir::root();
    for (const QString &part : parts) {
        if (trial.cd(part)) {
            const QFileInfo fi(trial.absolutePath());
            if (fi.isSymLink() && fi.symLinkTarget().startsWith(rootDir())) {
                qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << path << "already has a faking symlink" << trial.absolutePath();
                return true;
            }
            continue;
        }
        const QString realPath = QStringLiteral("%1/%2").arg(trial.absolutePath(), part);
        const QString fakePath = QStringLiteral("%1%2").arg(rootDir(), realPath);
        bool link_ret = QFile::link(fakePath, realPath);
        qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << "Symlinking" << realPath << "to" << fakePath << link_ret;
        return true;
    }
    return false;
}

bool PatchManagerFakeroot::tryToUnlinkParent(const QString &path)
{
    qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << path;
    const QStringList parts = path.split(QDir::separator(), QString::SkipEmptyParts);
    QDir trial = QDir::root();
    for (const QString &part : parts) {
        if (!trial.cd(part)) {
            qCWarning(patchmanagerDaemonLog) << Q_FUNC_INFO << "Failed when trying to change (cd) from directory" << trial.absolutePath() << "to" << part;
            return false;
        }
        const QFileInfo fi(trial.absolutePath());
        if (fi.isSymLink() && fi.symLinkTarget().startsWith(rootDir())) {
            bool remove_ret = QFile::remove(trial.absolutePath());
            qCDebug(patchmanagerDaemonLog) << Q_FUNC_INFO << "Removing" << trial.absolutePath() << remove_ret;
            return true;
        }
    }
    return false;
}


QString PatchManagerFakeroot::rootDir()
{
    return s_patchmanagerCacheRoot;
}
