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

#ifndef PATCHMANAGER_LOCATIONS_H
#define PATCHMANAGER_LOCATIONS_H

#include <QString>

// locations
static const QString PATCHES_DIR            = QStringLiteral("/usr/share/patchmanager/patches");
static const QString PATCHES_WORK_DIR_PREFIX= QStringLiteral("/tmp/patchmanager3");
static const QString PATCHES_WORK_DIR       = QStringLiteral("%1/%2").arg(PATCHES_WORK_DIR_PREFIX, "work");
static const QString PATCHES_ADDITIONAL_DIR = QStringLiteral("%1/%2").arg(PATCHES_WORK_DIR_PREFIX, "patches");
static const QString PATCH_METADATA_FILE    = QStringLiteral("patch.json");
static const QString MANGLE_CONFIG_FILE     = QStringLiteral("/etc/patchmanager/manglelist.conf");

static const QString s_configLocation = QStringLiteral("/etc/patchmanager2.conf");

static const QString s_patchmanagerSocket    = QStringLiteral("/tmp/patchmanager-socket");
//static const QString s_patchmanagerCacheRoot = QStringLiteral("/tmp/patchmanager");

static const QString s_sessionBusConnection = QStringLiteral("pm3connection");

// helpers
static const QString PM_APPLY   = QStringLiteral("/usr/libexec/pm_apply");
static const QString PM_UNAPPLY = QStringLiteral("/usr/libexec/pm_unapply");

// external binaries
static const QString BIN_UNZIP        = QStringLiteral("/usr/bin/unzip");
static const QString BIN_TAR          = QStringLiteral("/bin/tar");
static const QString BIN_PKCON        = QStringLiteral("/usr/bin/pkcon");
static const QString BIN_SYSTEMCTL_U  = QStringLiteral("/usr/bin/systemctl-user");
static const QString BIN_RPM          = QStringLiteral("/bin/rpm");


#endif // PATCHMANAGER_LOCATIONS_H
