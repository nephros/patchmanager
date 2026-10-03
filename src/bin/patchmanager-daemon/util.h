/*
 * Copyright (C) 2013 Lucien XU <sfietkonstantin@free.fr>
 * Copyright (C) 2016 Andrey Kozhevnikov <coderusinbox@gmail.com>
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * "Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * The names of its contributors may not be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#ifndef PATCHMANAGER_UTIL_H
#define PATCHMANAGER_UTIL_H

/*!
    Compares two dot-separated version strings \a version1 and \a version2, and
    returns the semantically higher one.
*/
static QString maxVersion(const QString &version1, const QString &version2)
{
    const QStringList vnums1 = version1.split(QChar('.'));
    const QStringList vnums2 = version2.split(QChar('.'));

    if (vnums1.count() < 3 || vnums2.count() < 3) {
        return version1;
    }

    for (int i = 0; i < 3; i++) {
        const QString vnum1 = vnums1.at(i);
        const QString vnum2 = vnums2.at(i);

        bool ok = false;
        const int num1 = vnum1.toInt(&ok);
        if (!ok) {
            continue;
        }
        const int num2 = vnum2.toInt(&ok);
        if (!ok) {
            continue;
        }
        if (num1 == num2) {
            continue;
        }
        if (num1 > num2) {
            return version1;
        }
        return version2;
    }

    return version1;
}

static QString pathToMangledPath(const QString &path, const QStringList &candidates)
{
    // Create mangling replacement tokens.
    QStringList toManglePaths = candidates;
    QStringList mangledPaths = candidates;
    mangledPaths.replaceInStrings("/usr/lib/", "/usr/lib64/");
    if (Q_PROCESSOR_WORDSIZE == 4) { // 32 bit
        std::swap(toManglePaths, mangledPaths);
    }
    qDebug() << Q_FUNC_INFO << "toManglePaths" << toManglePaths;
    qDebug() << Q_FUNC_INFO << "mangledPaths" << mangledPaths;

    QString newpath = path;

    for (int i = 0; i < toManglePaths.size(); i++) {
        // we need to deal with either absolute, or "git-style" beginnings, see #426:
        QString checkpath = path.mid(path.indexOf('/', 0));
        if (checkpath.startsWith(toManglePaths[i])) {
            qDebug() << Q_FUNC_INFO << "Mangle: Editing path: " << path;
            newpath.replace(toManglePaths[i], mangledPaths[i]);
            qDebug() << Q_FUNC_INFO << "Mangle: Edited path: " << path;
        }
    }
    qDebug() << Q_FUNC_INFO << "Path after mangle" << newpath;
    return newpath;
}

#endif // PATCHMANAGER_UTIL_H
