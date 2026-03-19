claude --verbose  --output-format stream-json --dangerously-skip-permissions  --append-system-prompt "" -p << EOF
 /ralph-loop:ralph-loop  $1 --max-iterations  20


EOF
