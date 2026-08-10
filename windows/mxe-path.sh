# shellcheck shell=sh

# Keep ccache-backed MXE compiler drivers available after Debian's /etc/profile
# replaces the image-level PATH for login shells.
case ":${PATH}:" in
*:/opt/mxe/usr/bin:*) ;;
*) export PATH="/opt/mxe/usr/bin:${PATH}" ;;
esac
case ":${PATH}:" in
*:/opt/mxe/.ccache/bin:*) ;;
*) export PATH="/opt/mxe/.ccache/bin:${PATH}" ;;
esac
