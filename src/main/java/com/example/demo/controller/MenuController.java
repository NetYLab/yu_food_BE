package com.example.demo.controller;

// MenuController.java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.demo.entity.Menu;
import com.example.demo.service.MenuService;

import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:3000")
public class MenuController {
    private final MenuService menuService;

    @Autowired
    public MenuController(MenuService menuService) {
        this.menuService = menuService;
    }

    @GetMapping("/menu/{rid}")
    public ResponseEntity<List<Menu>> getMenusByRestaurantId(@PathVariable Integer rid) {
        List<Menu> menus = menuService.getMenusByRestaurantId(rid);
        return ResponseEntity.ok(menus);
    }

    @PostMapping("/menu/{rid}")
    public ResponseEntity<Menu> addMenu(@PathVariable Integer rid, @RequestBody Menu menu) {
        Menu savedMenu = menuService.addMenu(menu, rid);
        return ResponseEntity.ok(savedMenu);
    }

    @PutMapping("/menu/{mid}")
    public ResponseEntity<Menu> updateMenu(@PathVariable Integer mid, @RequestBody Menu menu) {
        menu.setMid(mid);
        Menu updatedMenu = menuService.updateMenu(menu);
        return ResponseEntity.ok(updatedMenu);
    }

    @DeleteMapping("/menu/{mid}")
    public ResponseEntity<Void> deleteMenu(@PathVariable Integer mid) {
        menuService.deleteMenu(mid);
        return ResponseEntity.ok().build();
    }
}