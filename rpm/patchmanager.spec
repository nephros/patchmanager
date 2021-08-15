%define theme sailfish-default

%{!?qtc_qmake:%define qtc_qmake %qmake}
%{!?qtc_qmake5:%define qtc_qmake5 %qmake5}
%{!?qtc_make:%define qtc_make make}
%{?qtc_builddir:%define _builddir %qtc_builddir}

Name:       patchmanager

Summary:    Patchmanager allows you to manage Sailfish OS patches
Version:    2.4.2.2
Release:    1
Group:      Qt/Qt
License:    TODO
URL:        https://github.com/sailfishos-patches/patchmanager
Source0:    %{name}-%{version}.tar.bz2
Requires:   ausmt >= 1.3.0
Requires:   unzip
Requires:   dbus
Conflicts:  jolla-settings-%{name}
Obsoletes:  jolla-settings-%{name}
Conflicts:  %{name}-ui
Obsoletes:  %{name}-ui
# busybox bash/ash will hang QProcess in post install script
Conflicts:  busybox-symlinks-bash
Requires:   gnu-bash
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(Qt5Qml)
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(mlite5)
BuildRequires:  pkgconfig(sailfishapp) >= 0.0.10
BuildRequires:  pkgconfig(nemonotifications-qt5)
BuildRequires:  sailfish-svg2png >= 0.1.5

%description
patchmanager allows managing Sailfish OS patches
on your device easily.

%prep
%setup -q -n %{name}-%{version}

%build
%qtc_qmake5 
%qtc_make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%qmake5_install

%pre
case "$*" in
1)
echo Installing package
;;
2)
echo Upgrading package
;;
*) echo case "$*" not handled in pre
esac

%preun
case "$*" in
0)
echo Uninstalling package
if [ -d /var/lib/patchmanager/ausmt/patches/sailfishos-patchmanager-unapplyall ]; then
/usr/sbin/patchmanager -u sailfishos-patchmanager-unapplyall || true
fi

if /sbin/pidof patchmanager > /dev/null; then
dbus-send --system --type=method_call \
--dest=org.SfietKonstantin.patchmanager /org/SfietKonstantin/patchmanager \
org.SfietKonstantin.patchmanager.quit
fi
;;
1)
echo Upgrading package
if /sbin/pidof patchmanager > /dev/null; then
dbus-send --system --type=method_call \
--dest=org.SfietKonstantin.patchmanager /org/SfietKonstantin/patchmanager \
org.SfietKonstantin.patchmanager.quit
fi
;;
*) echo case "$*" not handled in preun
esac

%post
case "$*" in
1)
echo Installing package
dbus-send --system --type=method_call \
--dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
/usr/sbin/patchmanager -a sailfishos-patchmanager-unapplyall || true
;;
2)
echo Upgrading package
dbus-send --system --type=method_call \
--dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
/usr/sbin/patchmanager -a sailfishos-patchmanager-unapplyall || true
;;
*) echo case "$*" not handled in post
esac

%postun
case "$*" in
0)
echo Uninstalling package
dbus-send --system --type=method_call \
--dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
;;
1)
echo Upgrading package
dbus-send --system --type=method_call \
--dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
;;
*) echo case "$*" not handled in postun
esac

%files
%defattr(-,root,root,-)
%{_sbindir}/%{name}
%{_datadir}/%{name}/tools
%{_datadir}/dbus-1/
%{_sysconfdir}/dbus-1/system.d/
%{_datadir}/patchmanager/patches/sailfishos-patchmanager-unapplyall/patch.json
%{_datadir}/patchmanager/patches/sailfishos-patchmanager-unapplyall/unified_diff.patch

%{_libdir}/qt5/qml/org/SfietKonstantin/%{name}
%{_datadir}/%{name}/data
%{_datadir}/translations
%{_datadir}/jolla-settings/pages/%{name}
%{_datadir}/jolla-settings/entries/%{name}.json
%{_datadir}/%{name}/icons/icon-m-patchmanager.png

%{_datadir}/themes/%{theme}/meegotouch/z1.0/icons/*.png
%{_datadir}/themes/%{theme}/meegotouch/z1.25/icons/*.png
%{_datadir}/themes/%{theme}/meegotouch/z1.5/icons/*.png
%{_datadir}/themes/%{theme}/meegotouch/z1.5-large/icons/*.png
%{_datadir}/themes/%{theme}/meegotouch/z1.75/icons/*.png
%{_datadir}/themes/%{theme}/meegotouch/z2.0/icons/*.png
