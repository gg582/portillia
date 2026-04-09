<script lang="ts">
	import Sidebar from './Sidebar.svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();

	function close() {
		open = false;
	}
</script>

{#if open}
	<!-- Backdrop -->
	<div class="fixed inset-0 z-40 bg-black/50 lg:hidden" role="presentation">
		<button class="absolute inset-0 cursor-default" onclick={close} aria-label="Close navigation"
		></button>
	</div>

	<!-- Drawer -->
	<div
		class="fixed inset-y-0 left-0 z-50 w-72 overflow-y-auto border-r border-gray-200 bg-white p-6 lg:hidden dark:border-gray-700 dark:bg-gray-900"
	>
		<div class="mb-6 flex items-center justify-between">
			<span class="text-lg font-bold text-gray-900 dark:text-white">Portal Docs</span>
			<button
				onclick={close}
				class="rounded-lg p-1 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800"
				aria-label="Close navigation"
			>
				✕
			</button>
		</div>
		<!-- svelte-ignore event_directive_deprecated -->
		<div onclick={close} onkeydown={close} role="presentation">
			<Sidebar />
		</div>
	</div>
{/if}
