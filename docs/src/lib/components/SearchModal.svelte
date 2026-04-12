<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { tick } from 'svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();

	let query = $state('');
	let results = $state<Array<{ url: string; title: string; excerpt: string }>>([]);
	let activeIndex = $state(0);
	let loading = $state(false);
	let searchUnavailable = $state(false);
	let pagefind: any = null;
	let inputEl: HTMLInputElement | undefined = $state();
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;

	async function initPagefind() {
		if (pagefind) return;
		try {
			const path = '/pagefind/pagefind.js';
			pagefind = await import(/* @vite-ignore */ path);
		} catch {
			searchUnavailable = true;
		}
	}

	async function search(q: string) {
		if (!pagefind || !q.trim()) {
			results = [];
			return;
		}
		loading = true;
		try {
			const response = await pagefind.search(q);
			const items = await Promise.all(
				response.results.slice(0, 8).map(async (r: any) => {
					const data = await r.data();
					return {
						url: data.url,
						title: data.meta?.title || data.url,
						excerpt: data.excerpt
					};
				})
			);
			results = items;
			activeIndex = 0;
		} catch {
			results = [];
		} finally {
			loading = false;
		}
	}

	function handleInput(e: Event) {
		const value = (e.target as HTMLInputElement).value;
		query = value;
		clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => search(value), 200);
	}

	function navigate(url: string) {
		const path = url.replace(/\.html$/, '').replace(/index$/, '');
		goto(`${base}${path}`);
		close();
	}

	function close() {
		open = false;
		query = '';
		results = [];
		activeIndex = 0;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			activeIndex = Math.min(activeIndex + 1, results.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			activeIndex = Math.max(activeIndex - 1, 0);
		} else if (e.key === 'Enter' && results[activeIndex]) {
			e.preventDefault();
			navigate(results[activeIndex].url);
		} else if (e.key === 'Escape') {
			e.preventDefault();
			close();
		}
	}

	$effect(() => {
		if (open) {
			initPagefind();
			tick().then(() => inputEl?.focus());
		}
	});
</script>

{#if open}
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
	class="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
	onkeydown={handleKeydown}
>
	<!-- Backdrop -->
	<button
		class="absolute inset-0 bg-foreground/20 backdrop-blur-sm"
		onclick={close}
		aria-label="Close search"
		tabindex="-1"
	></button>

	<!-- Modal -->
	<div
		role="dialog"
		aria-modal="true"
		aria-label="Search documentation"
		class="relative z-10 mx-4 w-full max-w-xl overflow-hidden rounded-2xl border border-border/80 bg-background/95 shadow-2xl backdrop-blur-xl"
	>
		<!-- Search input -->
		<div class="flex items-center gap-3 border-b border-border/60 px-4 py-3">
			<svg class="h-5 w-5 shrink-0 text-text-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
				<path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
			</svg>
			<input
				bind:this={inputEl}
				type="text"
				placeholder="Search documentation..."
				value={query}
				oninput={handleInput}
				class="flex-1 bg-transparent text-base text-foreground outline-none placeholder:text-text-muted/60"
			/>
			<kbd class="rounded-md border border-border/60 px-1.5 py-0.5 text-[11px] font-medium text-text-muted">
				Esc
			</kbd>
		</div>

		<!-- Results -->
		<div class="max-h-[50vh] overflow-y-auto">
			{#if searchUnavailable}
				<div class="px-4 py-8 text-center text-sm text-text-muted">
					Search is available after building.<br />
					Run <code class="rounded bg-secondary px-1.5 py-0.5 text-xs">bun run build</code> to enable.
				</div>
			{:else if loading}
				<div class="px-4 py-8 text-center text-sm text-text-muted">Searching...</div>
			{:else if query && results.length === 0}
				<div class="px-4 py-8 text-center text-sm text-text-muted">
					No results for "<span class="font-medium text-foreground">{query}</span>"
				</div>
			{:else if results.length > 0}
				<ul class="py-2">
					{#each results as result, i}
						<li>
							<button
								class="w-full px-4 py-3 text-left transition-colors {i === activeIndex
									? 'bg-primary/10 text-foreground'
									: 'text-foreground/80 hover:bg-secondary/50'}"
								onclick={() => navigate(result.url)}
								onmouseenter={() => (activeIndex = i)}
							>
								<div class="text-sm font-semibold">{result.title}</div>
								{#if result.excerpt}
									<div class="mt-1 line-clamp-2 text-xs text-text-muted">
										{@html result.excerpt}
									</div>
								{/if}
							</button>
						</li>
					{/each}
				</ul>
			{:else}
				<div class="px-4 py-8 text-center text-sm text-text-muted">
					Type to search documentation
				</div>
			{/if}
		</div>

		<!-- Footer -->
		<div class="flex items-center justify-between border-t border-border/60 px-4 py-2 text-[11px] text-text-muted">
			<div class="flex items-center gap-3">
				<span><kbd class="rounded border border-border/60 px-1 py-0.5">↑↓</kbd> navigate</span>
				<span><kbd class="rounded border border-border/60 px-1 py-0.5">↵</kbd> open</span>
				<span><kbd class="rounded border border-border/60 px-1 py-0.5">esc</kbd> close</span>
			</div>
			<span>Powered by Pagefind</span>
		</div>
	</div>
</div>
{/if}
