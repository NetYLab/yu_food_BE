package com.example.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.entity.Menu;
import com.example.demo.entity.Restaurant;
import com.example.demo.repository.MenuRepository;
import com.example.demo.repository.RestaurantRepository;

import java.util.List;

@Service
@Transactional(readOnly = true)
public class MenuService {
    private final MenuRepository menuRepository;
    private final RestaurantRepository restaurantRepository;

    @Autowired
    public MenuService(MenuRepository menuRepository, RestaurantRepository restaurantRepository) {
        this.menuRepository = menuRepository;
        this.restaurantRepository = restaurantRepository;
    }

    // fetch join을 사용하도록 수정
    public List<Menu> getMenusByRestaurantId(Integer rid) {
        // fetch join 사용
        return menuRepository.findByRestaurantIdWithFetchJoin(rid);
        
        // 또는 EntityGraph 사용
        // return menuRepository.findByRestaurant_Rid(rid);
    }

    @Transactional
    public Menu addMenu(Menu menu, Integer rid) {
        Restaurant restaurant = restaurantRepository.findById(rid)
            .orElseThrow(() -> new RuntimeException("Restaurant not found"));
        menu.setRestaurant(restaurant);
        return menuRepository.save(menu);
    }

    @Transactional
    public void deleteMenu(Integer mid) {
        menuRepository.deleteById(mid);
    }

    @Transactional
    public Menu updateMenu(Menu menu) {
        return menuRepository.save(menu);
    }
}