setup:
	npm ci --ignore-scripts
	node scripts/install-opa.mjs
	npm run build

check:
	npm run verify

demo:
	npm run demo

run:
	npm start
