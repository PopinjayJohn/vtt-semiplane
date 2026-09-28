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
// vendored DataStar bundle all come out of the binary under /_/assets/.
//
// DataStar 1.0 syntax, not the beta form: data-on:click, never data-on-click.

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
	 * Moves focus and scroll after a region was replaced.
	 *
	 * The listener is on the document rather than on the region, because the
	 * region is the thing that was just replaced: an element that no longer
	 * exists cannot receive the event that announces its own arrival.
	 */
	function watchForSwaps() {
		document.addEventListener('datastar-patch-elements', () => {
			const region = document.getElementById(REGION);
			if (!region) {
				return;
			}
			const target = region.querySelector(FOCUSABLE) || region;
			if (target === region) {
				region.setAttribute('tabindex', '-1');
			}
			// preventScroll keeps the two from fighting: the scroll is set
			// explicitly on the next frame, and a focus that also scrolled would
			// land the viewport somewhere neither of them chose.
			target.focus({ preventScroll: true });
			window.scrollTo({ top: 0, behavior: 'instant' });
			markCurrentLink();
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

	function start() {
		markCurrentLink();
		watchForSwaps();
		relabelTimestamps();
		tidySearchForm();
		warnOnUnhandledEnhancedLinks();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', start, { once: true });
	} else {
		start();
	}
})();
