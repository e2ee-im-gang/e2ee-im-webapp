import svelte from 'rollup-plugin-svelte';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import { terser } from 'rollup-plugin-terser';
import builtins from 'rollup-plugin-node-builtins';
import globals from 'rollup-plugin-node-globals';

const production = !process.env.ROLLUP_WATCH;

export default [{
	input: 'src/login.js',
	output: {
		sourcemap: true,
		format: 'iife',
		name: 'login',
		file: 'public/login.js'
	},
	plugins: [
		svelte({
			// enable run-time checks when not in production
			dev: !production,
			// we'll extract any component CSS out into
			// a separate file — better for performance
			css: css => {
				css.write('public/login.css');
			}
		}),

		// If you have external dependencies installed from
		// npm, you'll most likely need these plugins. In
		// some cases you'll need additional configuration —
		// consult the documentation for details:
		// https://github.com/rollup/rollup-plugin-commonjs
		resolve({
			browser: true,
			dedupe: importee => importee === 'svelte' || importee.startsWith('svelte/')
		}),
        commonjs(),
        globals(),
        builtins(),

		// If we're building for production (npm run build
		// instead of npm run dev), minify
		production && terser()
	],
	watch: {
		clearScreen: false
	}
}, {
    input: 'src/create_account.js',
	output: {
		sourcemap: true,
		format: 'iife',
		name: 'create_account',
		file: 'public/create_account.js'
	},
	plugins: [
		svelte({
			dev: !production,
			css: css => {
				css.write('public/create_account.css');
			}
		}),
		resolve({
			browser: true,
			dedupe: importee => importee === 'svelte' || importee.startsWith('svelte/')
		}),
        commonjs(),
        globals(),
        builtins(),
		production && terser()
	],
	watch: {
		clearScreen: false
	}
}, {
    input: 'src/home.js',
	output: {
		sourcemap: true,
		format: 'iife',
		name: 'home',
		file: 'public/home.js'
	},
	plugins: [
		svelte({
			dev: !production,
			css: css => {
				css.write('public/home.css');
			}
		}),
		resolve({
			browser: true,
			dedupe: importee => importee === 'svelte' || importee.startsWith('svelte/')
		}),
        commonjs(),
        globals(),
        builtins(),
		production && terser()
	],
	watch: {
		clearScreen: false
	}
}];

