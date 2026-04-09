<script lang="ts">
	import { page } from '$app/stores';
	import { base } from '$app/paths';
	import { navigation } from '$lib/nav';

	const currentPath = $derived($page.url.pathname);
</script>

<nav class="space-y-6" aria-label="Documentation">
	{#each navigation as section}
		<div>
			<h3
				class="flex items-center gap-2 font-display text-xs font-semibold tracking-wider text-gray-500 uppercase dark:text-gray-400"
			>
				{section.title}
				{#if section.badge}
					<span
						class="rounded-full border border-amber-400/25 bg-amber-400/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400"
					>
						{section.badge}
					</span>
				{/if}
			</h3>
			<ul class="mt-2 space-y-1">
				{#each section.items as item}
					{@const isActive =
						currentPath === `${base}${item.href}/` || currentPath === `${base}${item.href}` || currentPath.startsWith(`${base}${item.href}/`)}
					<li>
						<a
							href="{base}{item.href}"
							class="block rounded-lg px-3 py-2 text-sm transition-colors {isActive
								? 'bg-primary/10 font-medium text-primary dark:bg-primary-light/15 dark:text-primary-light'
								: 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-white/6'}"
							aria-current={isActive ? 'page' : undefined}
						>
							{item.title}
						</a>
					</li>
				{/each}
			</ul>
		</div>
	{/each}
</nav>
