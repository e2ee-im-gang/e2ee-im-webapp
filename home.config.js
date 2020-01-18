import svelte from 'rollup-plugin-svelte';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import { terser } from 'rollup-plugin-terser';
import builtins from 'rollup-plugin-node-builtins';
import globals from 'rollup-plugin-node-globals';

const production = !process.env.ROLLUP_WATCH;

export default {
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
};
