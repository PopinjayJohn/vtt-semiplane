// app.js — the shell's behaviour.
//
// Everything in this file is an enhancement. With this file blocked, missing,
// slow or erroring, every link is an ordinary link, every form is an ordinary
// form, and the page is complete: there is no state that exists only in
// JavaScript, no control that only appears once this has run, and no content
// that is fetched rather than rendered. The server sends the whole document on
// the first request and a fragment only when something asks for one by sending
// the DataStar request header, which is the same contract DataStar's own
// `get` action speaks.
//
// No remote origin is contacted. There is no import, no fetch of a third-party
// URL, and no analytics. The stylesheet, this file, the icon sprite and the
// vendored DataStar bundle all come out of the binary under /_/assets/. The one
// request this file opens is the push stream, and it is this origin.
//
// DataStar 1.0 syntax, not the beta form: data-on:click, never data-on-click.
// The bundle is an ES module that talks to the rest of the page through two
// events on `document`. `datastar-ready` is dispatched once, when the bundle
// has initialised. `datastar-fetch` is dispatched for every action it runs,
// with a detail of `{type, el, argsRaw}` where `type` names the action — so
// `datastar-fetch` with `type: "datastar-patch-signals"` is how a signal is
// written from outside, and `type: "datastar-patch-elements"` is how a swap
// announces itself. There is no DOM event named `datastar-patch-elements`:
// a bundle that never loads costs a console line and nothing else, which is
// the only reason to speak this protocol instead of reaching into it.

(() => {
	'use strict';

	// The id of the element a navigation replaces. It is the same id the
	// server puts on the region it renders as a fragment, which is what makes
	// the two halves of the negotiation agree without either of them knowing
	// the other's name beyond this constant.
	const REGION = 'page-region';

	// The attribute that opts a link into an in-place navigation. It is present
	// on the element in the markup rather than applied here, so that a reader
	// who inspects the source sees which links are enhanced and a link that
	// should not be enhanced cannot be enhanced by a wildcard.
	const ENHANCE = 'data-on:click';

	// A focusable element to move focus to after a swap. A region swap that
	// leaves focus on the link that was clicked is disorienting: a keyboard user
	// who activates a link expects the new content to be announced, and a
	// sighted user expects the viewport to have moved.
	const FOCUSABLE = 'h1, h2, [data-focus-target]';

	// The attribute the server puts on a swapped region to name it. It is read
	// as text and never as markup, and it is the only thing the swap protocol
	// announces: a title says which page arrived, it does not say what is in it.
	const PAGE_TITLE = 'data-page-title';

	// The visually hidden live region the swap protocol writes into. Absent in
	// a shell that does not ship one, in which case announcing is a no-op.
	const STATUS = '#live-status';

	// The two DataStar events, and the two action names this file uses.
	const DATASTAR_FETCH = 'datastar-fetch';
	const DATASTAR_READY = 'datastar-ready';
	const PATCH_ELEMENTS = 'datastar-patch-elements';
	const PATCH_SIGNALS = 'datastar-patch-signals';

	// Every signal is written with the framework's own prefix, so a name here
	// is exactly the name in the markup's `$_leftOpen`.
	const SIGNAL_PREFIX = '$_';

	// The push stream. It is this origin's route and takes the page being
	// shown, because a subscriber is only ever pushed for the page it has open.
	const EVENTS_PATH = '/_/events';

	// The manual theme override. The cookie holds `dark` or `light`; its
	// absence means follow the operating system, which is also what happens
	// with this file blocked. web/src/input.css reads the same two class names
	// on the root element, and sets color-scheme from them, which is what every
	// light-dark() token in the theme resolves against.
	const THEME_COOKIE = 'semiplane_theme';
	const THEME_CLASSES = ['dark', 'light', 'dark-forced'];
	const THEME_VALUES = ['light', 'dark', ''];

	// The event a push produces. It carries the reason and nothing else.
	const REFRESH_EVENT = 'semiplane-refresh';

	// How long the `g` chord waits for its second key. Long enough to type it
	// deliberately, short enough that a chord abandoned to look at something
	// else has expired before the next one starts.
	const CHORD_MS = 1200;

	// How long a swap stays armed while the response is in flight. The arming
	// is one-shot: a patch that never arrives must not leave an observer on the
	// region for the life of the document.
	const SWAP_ARM_MS = 5000;

	// A title in a live region is a title, not content, but it is still text
	// off the page, so it is bounded before it is announced.
	const TITLE_MAX = 160;

	// Where a `g` chord goes. The selector is what makes the binding honest:
	// if this document has no link to that destination, the deployment has no
	// such page and the key does nothing, because a shortcut that navigates to
	// a route the server does not mount is a broken control.
	const GO_TARGETS = {
		h: { href: '/', match: '[data-go="home"], a[href="/"]' },
		s: { href: '/search', match: '[data-go="search"], a[href="/search"]' },
		t: { href: '/tags', match: '[data-go="tags"], a[href="/tags"]' },
		f: { href: '/files', match: '[data-go="files"], a[href="/files"]' },
	};

	// The header search box. The first match in document order is the header's,
	// because the header is the first thing in the shell.
	const SEARCH_BOX = 'header input[name="q"], form[data-search] input[name="q"], input[type="search"]';

	// What the edit key acts on. The server renders this link only for a
	// principal who may write, so its absence is the permission check and
	// there is nothing for `e` to do.
	const EDIT_LINK = 'a[data-edit-href]';

	// A roving-tabindex group, its items, and the control that expands a tree
	// directory. A group that marks its items says so with data-roving-item; a
	// group that does not — the file tree, whose items *are* its links and its
	// directory buttons — is the set of things in it a keyboard can reach. Both
	// are one implementation because the model is the same: the group's items,
	// in document order, exactly one of them in the tab order.
	//
	// The tree's control is clicked rather than the attribute written: the
	// control runs the expression that drives the visual state, so the two
	// cannot come apart.
	const ROVING = '[data-roving]';
	const ROVING_ITEM = '[data-roving-item]';
	const ROVING_REACHABLE = 'a[href], button, [role="treeitem"]';
	const TREE_CONTROL = '[data-tree-toggle], summary';

	// Whatever an overlay was opened from, so Esc can hand focus back to it.
	const TRIGGER = 'button, a, summary, [role="button"], [popovertarget]';

	// The two sidebars stop being columns at these widths. At or above the
	// width a sidebar is part of the grid, so there is nothing for Esc to close
	// and nothing for the toggle key to toggle.
	const DRAWER_LEFT = '(max-width: 1023px)';
	const DRAWER_RIGHT = '(max-width: 1279px)';

	// The things Esc can close, in the order they are checked: a dialog is
	// above a drawer and a dialog is above a dialog, so the first one that is
	// open is the one Esc closes. Each names the signal the markup binds its
	// open state to — the palette and the shortcut list to $openPalette and
	// $openShortcuts, the sidebars to $_leftOpen and $_rightOpen — and the
	// signal is the only way any of them is opened or closed, because the
	// trigger's aria-expanded and the element's visibility are both bound to
	// it.
	const SPEC_PALETTE = { selector: '#palette', signal: 'openPalette', drawer: null };
	const SPEC_SHORTCUTS = { selector: '#shortcuts', signal: 'openShortcuts', drawer: null };
	const SPEC_LEFT = { selector: '#left-nav', signal: 'leftOpen', drawer: DRAWER_LEFT };
	const SPEC_RIGHT = { selector: '#context', signal: 'rightOpen', drawer: DRAWER_RIGHT };
	const OVERLAYS = [SPEC_PALETTE, SPEC_SHORTCUTS, SPEC_LEFT, SPEC_RIGHT];

	// The chord in progress, and the element that opened the last overlay.
	// Both are the only mutable state in this file, and neither is the state of
	// anything: both are recomputed from the document.
	const chord = { key: null, timer: 0 };
	let lastTrigger = null;

	// The push stream, if this page has one. There is one per tab and never one
	// per region: two subscriptions would double every render.
	let stream = null;
	let pushWanted = false;
	let pushPath = '';

	// The armed swap watch, if a patch is in flight.
	let swapWatch = null;
	let swapTimer = 0;

	const mediaCache = new Map();

	/**
	 * Evaluates a media query, once.
	 *
	 * The map exists because these queries are asked on every keystroke and
	 * matchMedia is not free, and it is unbounded in practice: the table above
	 * is the whole set of queries this file asks.
	 */
	function mediaMatches(query) {
		if (!mediaCache.has(query)) {
			mediaCache.set(query, window.matchMedia(query));
		}
		return mediaCache.get(query).matches;
	}

	/**
	 * Writes one DataStar signal from outside the framework.
	 *
	 * The patch is dispatched rather than the element set, so that the signal
	 * the visual state and the aria state are bound to stays the only state
	 * there is: nothing in this file knows what "open" looks like, so the two
	 * cannot disagree.
	 */
	function setSignal(name, value) {
		const patch = {};
		patch[SIGNAL_PREFIX + name] = value;
		document.dispatchEvent(new CustomEvent(DATASTAR_FETCH, {
			detail: { type: PATCH_SIGNALS, argsRaw: { signals: JSON.stringify(patch) } },
		}));
	}

	/**
	 * Whether an element is currently showing.
	 *
	 * DataStar's data-show writes display:none inline, so an element with no
	 * client rects is closed and one with rects is open. The dialog cases are
	 * there because a <dialog> can be open with no box of its own to measure.
	 */
	function isOpen(el) {
		if (!el) {
			return false;
		}
		if (el.tagName === 'DIALOG') {
			return el.open === true;
		}
		if (el.hasAttribute('hidden')) {
			return false;
		}
		return el.getClientRects().length > 0;
	}

	/**
	 * The topmost thing Esc can close, or null.
	 *
	 * A native dialog wins outright: it is the innermost thing on the page and
	 * the only one the browser would close on Esc by itself.
	 */
	function topOpenOverlay() {
		const dialog = document.querySelector('dialog[open]');
		if (dialog) {
			for (const spec of OVERLAYS) {
				if (spec.selector === '#' + dialog.id) {
					return { el: dialog, signal: spec.signal };
				}
			}
			// A dialog this file has no signal for cannot be closed through
			// one, and the browser closes it on Esc by itself.
			return null;
		}
		for (const spec of OVERLAYS) {
			if (spec.drawer && !mediaMatches(spec.drawer)) {
				continue;
			}
			const el = document.querySelector(spec.selector);
			if (isOpen(el)) {
				return { el, signal: spec.signal };
			}
		}
		return null;
	}

	/**
	 * Whether anything is open, so that the rest of the map knows it is talking
	 * to a page behind a dialog rather than to the dialog.
	 */
	function hasOpenOverlay() {
		return topOpenOverlay() !== null;
	}

	/**
	 * Remembers what an overlay was opened from, so Esc can put focus back.
	 *
	 * The focused element is the trigger for a keyboard-opened overlay; for a
	 * pointer-opened one it is the clicked control, recorded by watchTriggers.
	 */
	function rememberTrigger() {
		const active = document.activeElement;
		if (active && active !== document.body && active !== document.documentElement) {
			lastTrigger = active;
		}
	}

	/**
	 * Records the control a click started on.
	 *
	 * Capture phase, and on the document, because the trigger is the element
	 * the click began on and DataStar may have replaced it by the time a
	 * bubbling listener would run.
	 */
	function watchTriggers() {
		document.addEventListener(
			'click',
			(event) => {
				const node = event.target;
				if (!node || node.nodeType !== 1) {
					return;
				}
				const trigger = node.closest(TRIGGER);
				if (trigger) {
					lastTrigger = trigger;
				}
			},
			true,
		);
	}

	/**
	 * Opens an overlay. A no-op when the element is not in the document.
	 *
	 * The signal is used even for a real <dialog>, rather than showModal:
	 * the dialog's open attribute and the trigger's aria-expanded are both
	 * bound to that signal, and opening the element behind the signal's back
	 * is the disagreement §3.5 exists to prevent.
	 */
	function openOverlay(spec) {
		const el = document.querySelector(spec.selector);
		if (!el) {
			return false;
		}
		rememberTrigger();
		setSignal(spec.signal, true);
		return true;
	}

	/**
	 * Toggles a sidebar.
	 *
	 * The new value is read from the element rather than from a remembered one,
	 * so the header's own toggle button and this key cannot drift apart: both
	 * write the same signal and the element is the state.
	 */
	function toggleDrawer(spec, event) {
		if (spec.drawer && !mediaMatches(spec.drawer)) {
			return;
		}
		const el = document.querySelector(spec.selector);
		if (!el) {
			return;
		}
		rememberTrigger();
		setSignal(spec.signal, !isOpen(el));
		event.preventDefault();
	}

	/**
	 * Navigates the way a click would.
	 *
	 * An anchor's own activation is the navigation: DataStar intercepts the
	 * click and swaps the region when it is loaded, and the browser follows the
	 * href when it is not, which is the whole enhancement contract. An element
	 * that only carries the URL as data falls back to a real navigation.
	 */
	function follow(el, href) {
		if (el && el.hasAttribute('href')) {
			el.click();
			return;
		}
		if (href) {
			window.location.assign(href);
		}
	}

	/**
	 * Runs the second key of a chord, or cancels it.
	 *
	 * A key the map does not claim is left alone: `g` followed by `q` cancels
	 * the chord and still types whatever `q` was going to do.
	 */
	function runChord(event) {
		const target = GO_TARGETS[event.key];
		clearChord();
		if (event.ctrlKey || event.metaKey || event.altKey) {
			return;
		}
		if (!target) {
			return;
		}
		follow(document.querySelector(target.match), target.href);
		event.preventDefault();
	}

	function clearChord() {
		chord.key = null;
		if (chord.timer) {
			window.clearTimeout(chord.timer);
			chord.timer = 0;
		}
	}

	function startChord(event) {
		clearChord();
		chord.key = 'g';
		chord.timer = window.setTimeout(clearChord, CHORD_MS);
		event.preventDefault();
	}

	/**
	 * Whether the keystroke is aimed at a field.
	 *
	 * Every binding except Ctrl/⌘+K in the search box is inert here, and that
	 * is what makes `?` a question mark in a search box rather than a shortcut.
	 */
	function isTypingTarget(node) {
		if (!node || node.nodeType !== 1) {
			return false;
		}
		if (node.isContentEditable) {
			return true;
		}
		return node.tagName === 'INPUT' || node.tagName === 'TEXTAREA' || node.tagName === 'SELECT';
	}

	/**
	 * Whether a component owns the keyboard. A roving group is a keyboard scope
	 * of its own, and a bare letter aimed at a focused file-tree link is a
	 * letter rather than a shortcut.
	 */
	function ownsItsKeys(node) {
		return Boolean(node) && node.nodeType === 1 && Boolean(node.closest(ROVING));
	}

	function isPaletteKey(event) {
		return (event.ctrlKey || event.metaKey) && !event.altKey && String(event.key).toLowerCase() === 'k';
	}

	/**
	 * Closes the topmost overlay and hands focus back to whatever opened it.
	 */
	function onEscape(event) {
		const top = topOpenOverlay();
		if (!top) {
			// Nothing was open, so the key belongs to whatever the reader is
			// actually in: a textarea that cancels an edit, a browser that
			// stops a find.
			return;
		}
		event.preventDefault();
		setSignal(top.signal, false);
		if (lastTrigger && lastTrigger.isConnected) {
			lastTrigger.focus();
		}
	}

	/**
	 * The keyboard map, bound once on the document.
	 *
	 * It is bound here rather than on a region so it survives every swap, and
	 * written as a chain of early returns so each key is a no-op when the
	 * element it acts on is absent. Tab is never handled: §3.4 leaves it alone.
	 */
	function onKeydown(event) {
		if (event.defaultPrevented || event.isComposing) {
			return;
		}

		// Esc is the one binding that works from anywhere. A drawer opened with
		// `[` and a palette opened with Ctrl+K have to be closable wherever the
		// reader has since moved focus to.
		if (event.key === 'Escape') {
			onEscape(event);
			return;
		}

		if (isTypingTarget(event.target) || ownsItsKeys(event.target)) {
			// The search box is the one field the map is not ignored in, and in
			// it the only binding that is not a character is Ctrl/⌘+K. `/` is not
			// handled here because the box already has focus, and handling it
			// would eat the character; `?` here is a question mark.
			if (isSearchBox(event.target) && isPaletteKey(event)) {
				event.preventDefault();
				openOverlay(SPEC_PALETTE);
			}
			return;
		}

		if (isPaletteKey(event)) {
			event.preventDefault();
			openOverlay(SPEC_PALETTE);
			return;
		}

		// Every remaining binding is a bare key. A modified one is the
		// platform's or a field's, and this file does not take it.
		if (event.ctrlKey || event.metaKey || event.altKey) {
			return;
		}

		// Everything below acts on the page behind an overlay, so with one
		// open the map is Esc and Ctrl/⌘+K and nothing else. `?` inside the
		// palette would otherwise stack a second dialog on the first.
		if (hasOpenOverlay()) {
			return;
		}

		if (chord.key !== null) {
			runChord(event);
			return;
		}

		switch (event.key) {
			case '/':
				focusSearch(event);
				return;
			case '[':
				toggleDrawer(SPEC_LEFT, event);
				return;
			case ']':
				toggleDrawer(SPEC_RIGHT, event);
				return;
			case '?':
				if (openOverlay(SPEC_SHORTCUTS)) {
					event.preventDefault();
				}
				return;
			case 'g':
				startChord(event);
				return;
			case 'e':
				activateEdit(event);
				return;
			default:
				break;
		}
	}

	/**
	 * Focuses the header search box.
	 *
	 * The box is selected as well as focused, because the reader asked to be
	 * at the search box and not to be at the start of a query they did not
	 * write. It is not preventDefault-ed when it is already focused, which is
	 * the only way `/` stays a character inside the box. And a box the layout
	 * has hidden — the header's search form is not on a phone — is not focused
	 * at all, because focusing an invisible control moves focus somewhere the
	 * reader cannot see and cannot get back from.
	 */
	function focusSearch(event) {
		const box = document.querySelector(SEARCH_BOX);
		if (!box || box.getClientRects().length === 0) {
			return;
		}
		if (document.activeElement !== box) {
			event.preventDefault();
			box.focus();
			if (typeof box.select === 'function') {
				box.select();
			}
		}
	}

	/**
	 * Edits the current page, for a principal the server rendered an edit link
	 * for. With the link absent the key does nothing: that absence is the
	 * permission check, and a client-side guess at it would be a second one.
	 */
	function activateEdit(event) {
		const link = document.querySelector(EDIT_LINK);
		if (!link) {
			return;
		}
		event.preventDefault();
		follow(link, link.getAttribute('data-edit-href'));
	}

	function bindKeys() {
		document.addEventListener('keydown', onKeydown);
	}

	/* The theme override. A preference, not state: nothing on the page changes
	 * with it except how the page is coloured, and the page is complete and
	 * correct without it. */

	function readCookie(name) {
		for (const part of document.cookie.split(';')) {
			const [key, ...rest] = part.trim().split('=');
			if (key === name) {
				return decodeURIComponent(rest.join('='));
			}
		}
		return '';
	}

	/**
	 * Resolves the theme into the one class the stylesheet reads.
	 *
	 * The class list is written whole rather than appended to, because the
	 * stylesheet treats a dark class and a light class as opposites and a page
	 * that has accumulated both would have no defined appearance at all.
	 */
	function applyTheme(value) {
		const root = document.documentElement;
		for (const name of THEME_CLASSES) {
			root.classList.remove(name);
		}
		if (value === 'dark' || value === 'light') {
			root.classList.add(value);
		}
	}

	function writeThemeCookie(value) {
		// A year, and SameSite=Lax because a theme is a preference and never a
		// secret — but it is a cookie either way, and the server does not read
		// it, so a reader who never uses the toggle has none.
		document.cookie =
			THEME_COOKIE +
			'=' +
			encodeURIComponent(value) +
			';path=/;max-age=31536000;samesite=lax';
	}

	/**
	 * Applies the stored override and wires the toggle, if the shell has one.
	 *
	 * The control is optional by design: the override is a preference and its
	 * absence must degrade to the operating system's answer, not to a button
	 * that does nothing.
	 */
	function watchTheme() {
		const stored = readCookie(THEME_COOKIE);
		applyTheme(stored === 'dark' || stored === 'light' ? stored : '');
		for (const control of document.querySelectorAll('[data-theme-toggle]')) {
			control.addEventListener('click', () => {
				const current = readCookie(THEME_COOKIE);
				const at = THEME_VALUES.indexOf(current === 'dark' || current === 'light' ? current : '');
				const next = THEME_VALUES[(at + 1) % THEME_VALUES.length];
				applyTheme(next);
				writeThemeCookie(next);
			});
		}
	}

	function isSearchBox(node) {
		return Boolean(node) && node === document.querySelector(SEARCH_BOX);
	}

	/**
	 * Marks the nav link for the page being shown.
	 *
	 * aria-current is the whole mechanism, and it is set from the URL rather than
	 * from the markup: a page rendered as a fragment did not go through a
	 * template that could have known which link to mark.
	 */
	function markCurrentLink() {
		const path = window.location.pathname;
		for (const link of document.querySelectorAll('nav a[href]')) {
			const href = link.getAttribute('href');
			const current = href === path || (href !== '/' && path.startsWith(href + '/'));
			if (current) {
				link.setAttribute('aria-current', 'page');
			} else {
				link.removeAttribute('aria-current');
			}
		}
	}

	/**
	 * The name of the page that has just arrived.
	 *
	 * The server's data-page-title is preferred because a fragment is rendered
	 * by a template that already knows the title; the region's own h1 and the
	 * document title are the fallbacks. All three are titles, none of them is
	 * content, and none of them comes from an event payload.
	 */
	function pageTitle(region) {
		const holder = region.matches('[' + PAGE_TITLE + ']')
			? region
			: region.querySelector('[' + PAGE_TITLE + ']');
		const marked = holder ? holder.getAttribute(PAGE_TITLE) : null;
		if (marked) {
			return marked.trim().slice(0, TITLE_MAX);
		}
		const heading = region.querySelector('h1');
		const text = heading ? heading.textContent : '';
		return (text || document.title || '').trim().slice(0, TITLE_MAX);
	}

	/**
	 * The live region the swap protocol writes into.
	 *
	 * The shell is expected to ship one, because the plan puts it in the markup
	 * next to the region it announces. It is created here when it is missing
	 * anyway: an in-place swap can only happen with this file, so a live region
	 * that exists only with this file is announcing only what this file can
	 * cause, and the alternative is a swap that moves focus and says nothing.
	 */
	function liveRegion() {
		const existing = document.getElementById(STATUS);
		if (existing) {
			return existing;
		}
		const status = document.createElement('div');
		status.id = STATUS;
		status.className = 'sr-only';
		status.setAttribute('role', 'status');
		status.setAttribute('aria-live', 'polite');
		status.setAttribute('aria-atomic', 'true');
		document.body.appendChild(status);
		return status;
	}

	/**
	 * Announces the swap in words and never in content.
	 *
	 * A live region that received a page's text would read the whole page aloud
	 * on every refresh, so the only thing that goes in is a title, and it is
	 * written as textContent so it cannot be markup.
	 */
	function announce(region) {
		const title = pageTitle(region);
		if (!title) {
			return;
		}
		liveRegion().textContent = title + ' loaded';
	}

	function disarmSwapWatch() {
		if (swapWatch) {
			swapWatch.disconnect();
			swapWatch = null;
		}
		if (swapTimer) {
			window.clearTimeout(swapTimer);
			swapTimer = 0;
		}
	}

	/**
	 * Waits for a patch to land.
	 *
	 * DataStar announces a patch when the request goes out, so at that moment
	 * the region still holds the page the reader is leaving. Moving focus onto
	 * that heading and announcing that page would be worse than doing nothing,
	 * so the work is deferred to the mutation the response causes, and the
	 * timer disarms the watch if the response turns out to be an error.
	 */
	function armSwapWatch() {
		const region = document.getElementById(REGION);
		if (!region) {
			return;
		}
		disarmSwapWatch();
		swapWatch = new MutationObserver((records) => {
			for (const record of records) {
				const changed = [...record.addedNodes, ...record.removedNodes].some(
					(node) => node.nodeType === 1,
				);
				if (!changed) {
					continue;
				}
				disarmSwapWatch();
				afterSwap(region);
				return;
			}
		});
		swapWatch.observe(region, { childList: true, subtree: true });
		swapTimer = window.setTimeout(disarmSwapWatch, SWAP_ARM_MS);
	}

	/**
	 * The element to focus after a swap.
	 *
	 * A heading is not focusable by default, and a focus call on one is a silent
	 * no-op — so the swap would leave the reader on a link that is no longer in
	 * the document. The heading is given tabindex="-1" first. This is not the
	 * aria-expanded / aria-current / aria-selected case §3.5 forbids: it is not
	 * state, it is the reachability the rule depends on, and the element is
	 * still not in the tab order.
	 */
	function focusTarget(region) {
		const target = region.querySelector(FOCUSABLE) || region;
		if (target.tabIndex < 0) {
			target.setAttribute('tabindex', '-1');
		}
		return target;
	}

	/**
	 * Moves focus and scroll after a region was replaced.
	 *
	 * The listener is on the document rather than on the region, because the
	 * region is the thing that was just replaced: an element that no longer
	 * exists cannot receive the event that announces its own arrival.
	 */
	function afterSwap(region) {
		const target = focusTarget(region);
		// preventScroll keeps the two from fighting: the scroll is set
		// explicitly on the next frame, and a focus that also scrolled would
		// land the viewport somewhere neither of them chose.
		target.focus({ preventScroll: true });
		window.scrollTo({ top: 0, behavior: 'instant' });
		markCurrentLink();
		announce(region);
	}

	/**
	 * Watches for a region swap.
	 *
	 * The bundle has no `datastar-patch-elements` DOM event to listen for: it
	 * dispatches `datastar-fetch` on the document with the action's name in the
	 * detail, which is what this listens for.
	 */
	function watchForSwaps() {
		document.addEventListener(DATASTAR_FETCH, (event) => {
			const detail = event.detail;
			if (!detail || detail.type !== PATCH_ELEMENTS) {
				return;
			}
			armSwapWatch();
		});
	}

	/**
	 * Makes a relative time in a card read as a relative time.
	 *
	 * The server writes the timestamp, and this only shortens what is already
	 * there. It runs against a data attribute rather than against text, so it
	 * cannot rewrite a page title that happens to look like a date.
	 */
	function relabelTimestamps() {
		const now = Date.now();
		for (const el of document.querySelectorAll('[data-updated-at]')) {
			const raw = el.getAttribute('data-updated-at');
			if (!raw) {
				continue;
			}
			const then = Date.parse(raw);
			if (Number.isNaN(then)) {
				continue;
			}
			const days = Math.floor((now - then) / 86400000);
			el.textContent = days <= 0 ? 'today' : days === 1 ? 'yesterday' : days + ' days ago';
		}
	}

	/**
	 * Refuses a search that is only whitespace.
	 *
	 * The form is a GET form, so with this file blocked an empty search reloads
	 * the page with an empty query, which the server answers with the empty
	 * form. Blocking it here saves a round trip and nothing else; the server
	 * does not depend on it.
	 */
	function tidySearchForm() {
		for (const form of document.querySelectorAll('form[data-search]')) {
			form.addEventListener('submit', (event) => {
				const field = form.querySelector('input[name="q"]');
				if (field && field.value.trim() === '') {
					event.preventDefault();
					field.focus();
				}
			});
		}
	}

	/**
	 * Reports a link that declared an enhancement but never got one.
	 *
	 * A data-on:click attribute with no DataStar behind it is an ordinary link
	 * and works, so there is nothing to repair. This exists so that the one case
	 * that is not a working link — an enhanced link that intercepts the click
	 * and then fails — is at least visible in the console to whoever hits it.
	 */
	function warnOnUnhandledEnhancedLinks() {
		if (window.__semiplaneDataStarReady) {
			return;
		}
		const enhanced = document.querySelectorAll('[' + ENHANCE + ']');
		if (enhanced.length > 0) {
			// eslint-disable-next-line no-console
			console.info(
				'semiplane: the data-star bundle did not initialise; every link will navigate normally'
			);
		}
	}

	/**
	 * Notes whether the vendored bundle initialised.
	 *
	 * Nothing else sets this flag, and the bundle announces itself from a queued
	 * effect, so the check has to wait for the load event: a flag read at
	 * DOMContentLoaded is read before the answer exists and reports a working
	 * bundle as a missing one.
	 */
	function watchDataStar() {
		document.addEventListener(DATASTAR_READY, () => {
			window.__semiplaneDataStarReady = true;
		});
		if (document.readyState === 'complete') {
			warnOnUnhandledEnhancedLinks();
			return;
		}
		window.addEventListener('load', warnOnUnhandledEnhancedLinks, { once: true });
	}

	/* Roving tabindex, shared by the file tree and the search result list. */

	/**
	 * The items in a roving group, in document order.
	 *
	 * A collapsed directory is display:none, and a group that counted its rows
	 * anyway is a group whose arrow keys walk into nothing: the reader presses
	 * Down and focus goes somewhere they cannot see. The visibility test is
	 * done for every item before any attribute is written, so the reads and the
	 * writes do not interleave and force a layout per item.
	 */
	function rovingItems(group) {
		const marked = group.querySelectorAll(ROVING_ITEM);
		const items = marked.length > 0 ? marked : group.querySelectorAll(ROVING_REACHABLE);
		const out = [];
		for (const item of items) {
			if (item.getClientRects().length > 0) {
				out.push(item);
			}
		}
		return out;
	}

	/**
	 * Puts exactly one item in the tab order.
	 *
	 * The item that already had it keeps it, so a background patch that
	 * rebuilds the list around the reader does not move their place in it.
	 */
	function initRoving(group) {
		const items = rovingItems(group);
		if (items.length === 0) {
			return;
		}
		let active = items.find((item) => item.getAttribute('tabindex') === '0');
		if (!active) {
			active = items[0];
		}
		for (const item of items) {
			item.setAttribute('tabindex', item === active ? '0' : '-1');
		}
	}

	function initAllRoving() {
		for (const group of document.querySelectorAll(ROVING)) {
			initRoving(group);
		}
	}

	/**
	 * Toggles a checkbox row's checkbox on Space.
	 *
	 * The checkbox keeps its own semantics: this presses it, so its change
	 * event still fires and whatever the markup bound to that event still
	 * happens. A Space aimed at the checkbox itself is left to the checkbox.
	 */
	function toggleRowCheckbox(item, event) {
		if (!item) {
			return false;
		}
		const box = item.querySelector('input[type="checkbox"]');
		if (!box || event.target === box) {
			return false;
		}
		box.click();
		event.preventDefault();
		return true;
	}

	/**
	 * Expands or collapses a tree directory.
	 *
	 * The control that owns the state is activated rather than aria-expanded
	 * being written here: the control runs the expression that drives the
	 * visual state, and the attribute is that same expression's output. In this
	 * shell the two are the same element — a directory's button is its state —
	 * and a markup that separates them puts the control inside the item, so
	 * both shapes are handled.
	 */
	function setTreeExpanded(item, expanded) {
		if (!item) {
			return false;
		}
		const state = item.getAttribute('aria-expanded');
		// No attribute is no state to change: a leaf has nothing to expand.
		if (state === null || (state === 'true') !== expanded) {
			return false;
		}
		const control = item.hasAttribute('aria-expanded') ? item : item.querySelector(TREE_CONTROL);
		if (!control) {
			return false;
		}
		control.click();
		return true;
	}

	/**
	 * Which of a group's items the event came from.
	 *
	 * A group that marks its items says so with data-roving-item; a group that
	 * does not is the file tree, whose item is whatever in it the reader has
	 * focused. Both are answered the same way — the nearest ancestor that is one
	 * of the items — so the two groups cannot take different paths through the
	 * handler that decides what a key does.
	 */
	function rovingItemOf(node, group, items) {
		for (let el = node; el && el !== group.parentElement; el = el.parentElement) {
			if (items.indexOf(el) >= 0) {
				return el;
			}
		}
		return null;
	}

	/**
	 * The group keydown handler, delegated from the document.
	 *
	 * preventDefault is called only for the keys this actually handles, so a
	 * focused link inside an item keeps its own Enter and Space, and Tab is
	 * never touched: this is a keyboard scope, not a keyboard prison.
	 */
	function onRovingKeydown(event) {
		const node = event.target;
		if (!node || node.nodeType !== 1 || event.defaultPrevented) {
			return;
		}
		const group = node.closest(ROVING);
		if (!group) {
			return;
		}
		const items = rovingItems(group);
		if (items.length === 0) {
			return;
		}
		const item = rovingItemOf(node, group, items);
		const at = item === null ? -1 : items.indexOf(item);

		let next = -1;
		if (event.key === 'ArrowDown') {
			next = at + 1;
		} else if (event.key === 'ArrowUp') {
			next = at - 1;
		} else if (event.key === 'Home') {
			next = 0;
		} else if (event.key === 'End') {
			next = items.length - 1;
		}
		if (next >= 0) {
			// Clamped rather than wrapped: the ends of a tree are the ends, and
			// Home and End exist so that a reader can get to one in one press.
			items[Math.max(0, Math.min(items.length - 1, next))].focus();
			event.preventDefault();
			return;
		}

		switch (event.key) {
			case 'Enter':
				// A group whose items are ordinary links is left to activate
				// itself: a click is the activation, and synthesising a second
				// one here would be a second navigation.
				if (!item || !item.hasAttribute('href')) {
					return;
				}
				item.click();
				event.preventDefault();
				return;
			case ' ':
			case 'Spacebar':
				toggleRowCheckbox(item, event);
				return;
			case 'ArrowRight':
				if (setTreeExpanded(item, true)) {
					event.preventDefault();
				}
				return;
			case 'ArrowLeft':
				if (setTreeExpanded(item, false)) {
					event.preventDefault();
				}
				return;
			default:
				break;
		}
	}

	/**
	 * Keeps the roving tab stops correct as the lists are rebuilt.
	 *
	 * A DataStar patch replaces a group's items and not the group, so the group
	 * is re-initialised on the patch and on any change inside it. `style` is in
	 * the filter because expanding a directory is a style change and not a
	 * childList one: the rows it reveals arrive in the document already, and
	 * without this they would keep whatever tabindex the server gave them and
	 * put the whole subtree back in the tab order. `tabindex` is deliberately
	 * not in the filter, so the writes below do not wake the observer.
	 */
	function watchRoving() {
		document.addEventListener(DATASTAR_FETCH, initAllRoving);
		document.addEventListener('keydown', onRovingKeydown);
		const observer = new MutationObserver((records) => {
			for (const record of records) {
				if (record.type === 'childList' || record.type === 'attributes') {
					initAllRoving();
					return;
				}
			}
		});
		observer.observe(document.body || document.documentElement, {
			childList: true,
			subtree: true,
			attributes: true,
			attributeFilter: ['style', 'hidden'],
		});
		initAllRoving();
	}

	/* The live-push client. §4.5: the stream carries a trigger, never content. */

	/**
	 * Reads the signals the server seeded on <body>.
	 *
	 * The parse is guarded because this attribute is the one piece of the
	 * contract that arrives as a string from a template. A malformed value has
	 * to cost the reader their live updates, not the whole shell.
	 */
	function readShellSignals() {
		const holder = document.body && document.body.getAttribute('data-signals') !== null
			? document.body
			: document.querySelector('[data-signals]');
		if (!holder) {
			return {};
		}
		try {
			const parsed = JSON.parse(holder.getAttribute('data-signals') || '{}');
			return parsed && typeof parsed === 'object' ? parsed : {};
		} catch {
			return {};
		}
	}

	/**
	 * Asks the shell to render again through the ordinary authorized handler.
	 *
	 * The event carries the reason and nothing else. A push that carried
	 * content would be a second rendering path with its own authorization
	 * bugs, which is the thing §4.5 exists to prevent; this is a trigger, and
	 * the bytes that reach the reader come from the same handler as a page load.
	 */
	function refresh(reason) {
		document.dispatchEvent(new CustomEvent(REFRESH_EVENT, { detail: { reason } }));
	}

	/**
	 * Handles one frame.
	 *
	 * A frame that will not parse is ignored rather than thrown: the stream is
	 * the reader's only notice that a page moved, and killing it over one bad
	 * frame would leave every later change unnoticed instead.
	 */
	function onFrame(event) {
		let frame;
		try {
			frame = JSON.parse(event.data);
		} catch {
			return;
		}
		if (!frame || typeof frame !== 'object') {
			return;
		}
		if (frame.type === 'reload' || frame.type === 'changed') {
			refresh(frame.type);
		}
	}

	function closeStream() {
		if (!stream) {
			return;
		}
		stream.close();
		stream = null;
	}

	/**
	 * Opens the stream, once, if this page has one.
	 *
	 * No push — an anonymous reader, a principal the server did not offer a
	 * stream to — means no stream and no stream quietly retrying. A tab that is
	 * not visible is not a page the server should be pushing to either.
	 */
	function openStream() {
		if (stream || !pushWanted || !pushPath || document.visibilityState === 'hidden') {
			return;
		}
		try {
			stream = new EventSource(EVENTS_PATH + '?page=' + encodeURIComponent(pushPath));
		} catch {
			return;
		}
		// `open` fires for the first connection and for every reconnection, so
		// this one listener is the unconditional refetch the contract asks for.
		// A frame that was dropped while the connection was down cannot be
		// accounted for, so the answer is always to render again rather than to
		// reason about what might have been missed.
		stream.addEventListener('open', () => refresh('open'));
		stream.addEventListener('message', onFrame);
		stream.addEventListener('error', () => {
			// EventSource reconnects by itself while the endpoint is merely
			// unreachable, and that reconnect arrives as another `open`. A
			// closed readyState is the browser giving up for good, and holding
			// the reference would stop a later visibilitychange from ever
			// opening a fresh one.
			if (stream && stream.readyState === EventSource.CLOSED) {
				closeStream();
			}
		});
	}

	/**
	 * Opens the stream for this page, if it has one.
	 */
	function startStream() {
		const signals = readShellSignals();
		// The value is a JSON boolean; the string form is accepted because a
		// template that interpolated it is the likeliest way to get it wrong,
		// and a reader silently losing live updates over that is a bad trade.
		pushWanted = signals.push === true || signals.push === 'true';
		pushPath = typeof signals.currentPageUrl === 'string' ? signals.currentPageUrl : '';
		// An empty path is a page the server pushes nothing for. The stream is
		// opened per page, so opening one here would be a subscription nobody
		// asked for.
		if (!pushWanted || !pushPath) {
			return;
		}
		openStream();
		window.addEventListener('pagehide', closeStream, { once: true });
		// A page restored from the back/forward cache comes back with a dead
		// stream and no visibilitychange to reopen it, which would leave it
		// permanently stale.
		window.addEventListener('pageshow', (event) => {
			if (event.persisted) {
				closeStream();
				openStream();
			}
		});
	}

	/**
	 * Opens and closes the stream with the tab.
	 *
	 * A hidden tab is not a page the server should be pushing to, and a hidden
	 * tab that reconnects every few seconds is a heartbeat nothing reads.
	 */
	function watchVisibility() {
		document.addEventListener('visibilitychange', () => {
			if (document.visibilityState === 'visible') {
				openStream();
			} else {
				closeStream();
			}
		});
	}

	/**
	 * Wires a typeahead input to the region named beside it.
	 *
	 * The markup carries `data-typeahead="<url prefix>"` on the input and
	 * `data-region-target="<selector>"` on the element that holds the rows, and
	 * this is the whole of the client half. It is a plain fetch and a plain DOM
	 * replacement rather than a DataStar action, and the reason is in
	 * internal/httpapi/datastar.go: the vendored bundle's element-patch wire
	 * format could not be established from outside with confidence, and its
	 * handling of an application/json response is a signals patch — so an
	 * `@get` here would either do nothing or write the results into the reactive
	 * store. The bytes still come from the server through the ordinary authorized
	 * handler; only the envelope is ours.
	 *
	 * Three things this has to get right, each of which is a bug otherwise:
	 *
	 *   - Out-of-order responses. A reader who types "dro" and then "drowned"
	 *     gets two requests, and the first can land second. Each carries the term
	 *     it was made for, and a response whose term is no longer what is in the
	 *     input is dropped rather than rendered.
	 *   - Never replacing the input. Only the rows region is written, so the
	 *     field being typed into keeps its focus, its caret and its selection
	 *     across every response.
	 *   - Inert markup never becomes a live control. With this file blocked the
	 *     form is an ordinary GET to a real page, which is why the same URL
	 *     answers a document.
	 */
	function wireTypeaheads(root) {
		const scope = root || document;
		for (const input of scope.querySelectorAll('input[data-typeahead]')) {
			if (input.dataset.typeaheadWired === 'true') {
				continue;
			}
			input.dataset.typeaheadWired = 'true';
			const prefix = input.getAttribute('data-typeahead');
			const delay = Number(input.getAttribute('data-typeahead-debounce')) || 150;
			const target = document.querySelector(input.getAttribute('data-region-target') || '');
			if (!prefix || !target) {
				// A typeahead with nowhere to put its answers is a control with
				// nothing behind it, which is a bug rather than a degradation. The
				// form still works; the rows just never arrive in place.
				continue;
			}
			let timer = null;
			let inFlight = null;
			let lastTerm = null;

			const render = (term, html) => {
				if (term !== input.value.trim()) {
					return;
				}
				// DOMParser + replaceChildren rather than innerHTML: it parses the
				// fragment the same way the browser parses a navigation, and it
				// cannot execute anything in it. The server already escaped
				// every value; this is a second belt, not the only one.
				const doc = new DOMParser().parseFromString(html, 'text/html');
				target.replaceChildren(...Array.from(doc.body.childNodes));
				lastTerm = term;
			};

			const run = () => {
				const term = input.value.trim();
				if (term === lastTerm) {
					return;
				}
				if (inFlight) {
					inFlight.abort();
				}
				const controller = new AbortController();
				inFlight = controller;
				input.setAttribute('data-busy', 'true');
				const url = prefix + encodeURIComponent(term);
				fetch(url, {
					signal: controller.signal,
					credentials: 'same-origin',
					headers: { Accept: 'text/html' },
				})
					.then((resp) => (resp.ok ? resp.text() : ''))
					.then((html) => {
						if (html) {
							render(term, html);
						}
					})
					.catch(() => {
						// A failed typeahead leaves the last good rows in place. A
						// reader who typed something the server refused should see
						// stale results, not an empty panel, and the form is still
						// right there to submit.
					})
					.finally(() => {
						if (inFlight === controller) {
							inFlight = null;
							input.removeAttribute('data-busy');
						}
					});
			};

			input.addEventListener('input', () => {
				if (timer) {
					clearTimeout(timer);
				}
				timer = setTimeout(run, delay);
			});
		}
	}

	function start() {
		markCurrentLink();
		watchForSwaps();
		relabelTimestamps();
		tidySearchForm();
		watchTriggers();
		watchTheme();
		bindKeys();
		watchRoving();
		watchDataStar();
		startStream();
		watchVisibility();
		wireTypeaheads();
		document.addEventListener('datastar-patch-elements', () => wireTypeaheads());
		document.addEventListener('semiplane-refresh', () => wireTypeaheads());
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', start, { once: true });
	} else {
		start();
	}
})();
