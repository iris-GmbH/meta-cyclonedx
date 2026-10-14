# Work around an rm_work defect of this generation: the stamp loop's
# catch-all removes the stamp of do_populate_lic_deploy, which is not an
# sstate task and is not named in a keep-case, so the license-manifest
# task rescheduled as real work in every warm invocation. oe-core fixed
# it later inside rm_work itself (master names the task in the
# keep-case); until this branch can take that, record the stamps around
# the deletion loop and restore them after. Only scheduling changes;
# the stamps are empty marker files whose name carries the hash, so
# the prefunc records names into a side file that the loop's glob
# (PF-prefixed) never sees. ${STAMP} is a generation-time expansion,
# like in rm_work's own body. Applied through INHERIT from kas.yml.

rm_work_save_populate_lic_deploy_stamps() {
	stampdir=`dirname "${STAMP}"`
	savelist="$stampdir/rmwork-lic-stamps.txt"
	: > "$savelist"
	for p in "$stampdir"/*.do_populate_lic_deploy.*; do
		[ -e "$p" ] || continue
		case "$p" in *.sigdata*) continue ;; esac
		printf '%s\n' "$p" >> "$savelist"
	done
}

rm_work_restore_populate_lic_deploy_stamps() {
	stampdir=`dirname "${STAMP}"`
	savelist="$stampdir/rmwork-lic-stamps.txt"
	[ -e "$savelist" ] || return 0
	while read -r p; do
		[ -e "$p" ] || : > "$p"
	done < "$savelist"
	rm -f "$savelist"
}
do_rm_work[prefuncs] += "rm_work_save_populate_lic_deploy_stamps"
do_rm_work[postfuncs] += "rm_work_restore_populate_lic_deploy_stamps"
